require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');
const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const USERS_FILE = path.join(__dirname, 'users.json');

// ─── CORS — allows the web app and iOS app to reach this server ───
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Raw body needed for Stripe webhook signature verification
app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ─── User store (JSON file — swap for a real DB before production) ───

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch { return {}; }
}
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ─── Auth middleware ───

function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        req.user = jwt.verify(header.slice(7), JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/config
//  Returns the Stripe publishable key so the web frontend never hardcodes it.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
    res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY });
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/messages
//  Serves messages.json — the single source of truth for all in-app and
//  website text: headline, subheadline, and update cards.
//  Edit Backend/messages.json to update both platforms without a release.
// ─────────────────────────────────────────────────────────────────────────────
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

app.get('/api/messages', (req, res) => {
    try {
        const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'public, max-age=60'); // clients may cache for 1 min
        res.send(data);
    } catch (err) {
        console.error('messages error:', err.message);
        res.status(500).json({ error: 'Could not load messages' });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/donor-count
//  Returns the number of registered users who have an active Stripe subscription.
//  Only returned when count > 100 (shown publicly on the home screen).
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/donor-count', async (req, res) => {
    try {
        const users = loadUsers();
        const customerIds = Object.values(users).map(u => u.customerId).filter(Boolean);

        let activeCount = 0;
        // Check each customer for an active subscription
        await Promise.all(customerIds.map(async (cid) => {
            const subs = await stripe.subscriptions.list({ customer: cid, status: 'active', limit: 1 });
            if (subs.data.length > 0) activeCount++;
        }));

        res.json({ count: activeCount, show: activeCount > 100 });
    } catch (err) {
        console.error('donor-count error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/register
//  Creates a web user account + a Stripe Customer linked by email.
//  Returns a JWT and the user's name/customerId.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'email, password, and name are required' });
        }

        const users = loadUsers();
        const key   = email.toLowerCase().trim();

        if (users[key]) {
            return res.status(409).json({ error: 'An account with that email already exists' });
        }

        // Reuse an existing Stripe customer for this email if one exists
        const existing = await stripe.customers.search({
            query: `email:'${key}'`,
            limit: 1,
        });

        let customerId;
        if (existing.data.length > 0) {
            customerId = existing.data[0].id;
        } else {
            const customer = await stripe.customers.create({
                email: key,
                name,
                metadata: { source: 'web' },
            });
            customerId = customer.id;
        }

        const passwordHash = await bcrypt.hash(password, 10);
        users[key] = { name, email: key, passwordHash, customerId, createdAt: new Date().toISOString() };
        saveUsers(users);

        const token = jwt.sign({ email: key, customerId, name }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token, name, customerId });
    } catch (err) {
        console.error('register error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/login
//  Authenticates an existing web user. Returns a JWT.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'email and password are required' });
        }

        const users = loadUsers();
        const key   = email.toLowerCase().trim();
        const user  = users[key];

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { email: key, customerId: user.customerId, name: user.name },
            JWT_SECRET,
            { expiresIn: '30d' }
        );
        res.json({ token, name: user.name, customerId: user.customerId });
    } catch (err) {
        console.error('login error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/me
//  Returns the logged-in user's profile + live subscription status from Stripe.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/me', requireAuth, async (req, res) => {
    try {
        const subs = await stripe.subscriptions.list({
            customer: req.user.customerId,
            status:   'active',
            limit:    1,
            expand:   ['data.items.data.price'],
        });

        let subscription = null;
        if (subs.data.length > 0) {
            const s     = subs.data[0];
            const price = s.items.data[0].price;
            subscription = {
                subscriptionId:  s.id,
                amountCents:     price.unit_amount,
                status:          s.status,
                nextBillingDate: new Date(s.current_period_end * 1000).toISOString().split('T')[0],
            };
        }

        res.json({
            email:      req.user.email,
            name:       req.user.name,
            customerId: req.user.customerId,
            subscription,
        });
    } catch (err) {
        console.error('me error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/create-customer
//  iOS app: identifies customers by deviceId.
//  Idempotent — returns existing customer if one already exists for that device.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/create-customer', async (req, res) => {
    try {
        const { deviceId } = req.body;
        if (!deviceId) return res.status(400).json({ error: 'deviceId is required' });

        const existing = await stripe.customers.search({
            query: `metadata['deviceId']:'${deviceId}'`,
            limit: 1,
        });

        if (existing.data.length > 0) {
            return res.json({ customerId: existing.data[0].id });
        }

        const customer = await stripe.customers.create({
            metadata: { deviceId },
        });

        res.json({ customerId: customer.id });
    } catch (err) {
        console.error('create-customer error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/create-subscription
//  Creates (or replaces) a monthly subscription for a customer.
//  Returns the PaymentIntent client_secret so the client can confirm payment.
//  Used by both the iOS app and the web frontend.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/create-subscription', async (req, res) => {
    try {
        const { customerId, amountCents } = req.body;
        if (!customerId || !amountCents) {
            return res.status(400).json({ error: 'customerId and amountCents are required' });
        }

        const cents = parseInt(amountCents, 10);
        if (isNaN(cents) || cents < 100) {
            return res.status(400).json({ error: 'Minimum donation is $1 (100 cents)' });
        }

        // Cancel any existing active subscription first
        const existing = await stripe.subscriptions.list({
            customer: customerId,
            status:   'active',
            limit:    10,
        });
        for (const sub of existing.data) {
            await stripe.subscriptions.cancel(sub.id);
        }

        const price = await stripe.prices.create({
            unit_amount:   cents,
            currency:      'usd',
            recurring:     { interval: 'month' },
            product_data:  { name: 'Monthly Charity Donation' },
        });

        const subscription = await stripe.subscriptions.create({
            customer:         customerId,
            items:            [{ price: price.id }],
            payment_behavior: 'default_incomplete',
            payment_settings: {
                save_default_payment_method: 'on_subscription',
                payment_method_types:        ['card'],
            },
            expand: ['latest_invoice.payment_intent'],
        });

        const paymentIntent = subscription.latest_invoice.payment_intent;

        res.json({
            subscriptionId: subscription.id,
            clientSecret:   paymentIntent.client_secret,
        });
    } catch (err) {
        console.error('create-subscription error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/subscription-status/:customerId
//  Returns the active subscription for a customer, or null if none.
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/subscription-status/:customerId', async (req, res) => {
    try {
        const { customerId } = req.params;

        const subscriptions = await stripe.subscriptions.list({
            customer: customerId,
            status:   'active',
            limit:    1,
            expand:   ['data.items.data.price'],
        });

        if (subscriptions.data.length === 0) {
            return res.json({ subscription: null });
        }

        const sub   = subscriptions.data[0];
        const price = sub.items.data[0].price;

        res.json({
            subscription: {
                subscriptionId:  sub.id,
                amountCents:     price.unit_amount,
                status:          sub.status,
                nextBillingDate: new Date(sub.current_period_end * 1000)
                                     .toISOString()
                                     .split('T')[0],
            },
        });
    } catch (err) {
        console.error('subscription-status error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/cancel-subscription
//  Cancels the subscription immediately.
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/cancel-subscription', async (req, res) => {
    try {
        const { subscriptionId } = req.body;
        if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });

        await stripe.subscriptions.cancel(subscriptionId);
        res.json({ success: true });
    } catch (err) {
        console.error('cancel-subscription error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/webhook
//  Receives Stripe events (payment success/failure, subscription changes).
//  Register this endpoint at https://dashboard.stripe.com/webhooks
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/webhook', (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error('Webhook signature error:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    switch (event.type) {
        case 'invoice.payment_succeeded':
            console.log('✅ Payment succeeded:', event.data.object.id);
            break;
        case 'invoice.payment_failed':
            console.warn('❌ Payment failed:', event.data.object.id);
            break;
        case 'customer.subscription.deleted':
            console.log('🚫 Subscription cancelled:', event.data.object.id);
            break;
        default:
            break;
    }

    res.json({ received: true });
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/donor-count
//  Returns the number of active monthly donors across web and iOS.
//  Result is cached for 5 minutes to avoid hammering the Stripe API.
// ─────────────────────────────────────────────────────────────────────────────
let donorCountCache = { count: 0, ts: 0 };
const COUNT_TTL     = 5 * 60 * 1000;

app.get('/api/donor-count', async (req, res) => {
    if (Date.now() - donorCountCache.ts < COUNT_TTL) {
        return res.json({ count: donorCountCache.count, show: donorCountCache.count > 100 });
    }
    try {
        let count = 0;
        for await (const _ of stripe.subscriptions.list({ status: 'active', limit: 100 })) {
            count++;
        }
        donorCountCache = { count, ts: Date.now() };
        res.json({ count, show: count > 100 });
    } catch (err) {
        console.error('donor-count error:', err.message);
        res.json({ count: donorCountCache.count, show: donorCountCache.count > 100 });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Charity Champ backend running on port ${PORT}`));
