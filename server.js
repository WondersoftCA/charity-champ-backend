require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const fs      = require('fs');
const path    = require('path');

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = (stripeKey && !stripeKey.includes('YOUR')) ? require('stripe')(stripeKey) : null;

function requireStripe(req, res, next) {
    if (!stripe) return res.status(503).json({ error: 'Payments are not configured yet.' });
    next();
}

const app        = express();
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const USERS_FILE = path.join(__dirname, 'users.json');

app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use('/api/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch { return {}; }
}
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

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

app.get('/api/config', (req, res) => {
    res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || null });
});

const MESSAGES_FILE = path.join(__dirname, 'messages.json');
app.get('/api/messages', (req, res) => {
    try {
        const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Cache-Control', 'public, max-age=60');
        res.send(data);
    } catch (err) {
        res.status(500).json({ error: 'Could not load messages' });
    }
});

app.get('/api/donor-count', async (req, res) => {
    if (!stripe) return res.json({ count: 0, show: false });
    try {
        let count = 0;
        for await (const _ of stripe.subscriptions.list({ status: 'active', limit: 100 })) {
            count++;
        }
        res.json({ count, show: count > 100 });
    } catch (err) {
        res.json({ count: 0, show: false });
    }
});

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

        let customerId = null;
        if (stripe) {
            const existing = await stripe.customers.search({ query: `email:'${key}'`, limit: 1 });
            if (existing.data.length > 0) {
                customerId = existing.data[0].id;
            } else {
                const customer = await stripe.customers.create({ email: key, name, metadata: { source: 'app' } });
                customerId = customer.id;
            }
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

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'email and password are required' });
        }

        const users = loadUsers();
        const key   = email.toLowerCase().trim();
        const user  = users[key];

        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

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

app.get('/api/me', requireAuth, requireStripe, async (req, res) => {
    try {
        const subs = await stripe.subscriptions.list({
            customer: req.user.customerId,
            status:   'active',
            limit:    1,
            expand:   ['data.items.data.price'],
        });

        let subscription = null;
        if (subs.data.length > 0) {
            const s = subs.data[0];
            const price = s.items.data[0].price;
            subscription = {
                subscriptionId:  s.id,
                amountCents:     price.unit_amount,
                status:          s.status,
                nextBillingDate: new Date(s.current_period_end * 1000).toISOString().split('T')[0],
            };
        }
        res.json({ email: req.user.email, name: req.user.name, customerId: req.user.customerId, subscription });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/create-subscription', requireStripe, async (req, res) => {
    try {
        const { customerId, amountCents } = req.body;
        if (!customerId || !amountCents) {
            return res.status(400).json({ error: 'customerId and amountCents are required' });
        }
        const cents = parseInt(amountCents, 10);
        if (isNaN(cents) || cents < 100) {
            return res.status(400).json({ error: 'Minimum donation is $1 (100 cents)' });
        }
        const existing = await stripe.subscriptions.list({ customer: customerId, status: 'active', limit: 10 });
        for (const sub of existing.data) await stripe.subscriptions.cancel(sub.id);

        const price = await stripe.prices.create({
            unit_amount: cents, currency: 'usd',
            recurring: { interval: 'month' },
            product_data: { name: 'Monthly Charity Donation' },
        });
        const subscription = await stripe.subscriptions.create({
            customer: customerId, items: [{ price: price.id }],
            payment_behavior: 'default_incomplete',
            payment_settings: { save_default_payment_method: 'on_subscription', payment_method_types: ['card'] },
            expand: ['latest_invoice.payment_intent'],
        });
        res.json({ subscriptionId: subscription.id, clientSecret: subscription.latest_invoice.payment_intent.client_secret });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/subscription-status/:customerId', requireStripe, async (req, res) => {
    try {
        const subs = await stripe.subscriptions.list({
            customer: req.params.customerId, status: 'active', limit: 1,
            expand: ['data.items.data.price'],
        });
        if (subs.data.length === 0) return res.json({ subscription: null });
        const sub = subs.data[0];
        const price = sub.items.data[0].price;
        res.json({ subscription: {
            subscriptionId: sub.id, amountCents: price.unit_amount,
            status: sub.status,
            nextBillingDate: new Date(sub.current_period_end * 1000).toISOString().split('T')[0],
        }});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/cancel-subscription', requireStripe, async (req, res) => {
    try {
        const { subscriptionId } = req.body;
        if (!subscriptionId) return res.status(400).json({ error: 'subscriptionId is required' });
        await stripe.subscriptions.cancel(subscriptionId);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/webhook', requireStripe, (req, res) => {
    const sig = req.headers['stripe-signature'];
    try {
        const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('Webhook:', event.type);
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    res.json({ received: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Charity Champ backend running on port ${PORT}`));
