require('dotenv').config();
const express = require('express');
const cors = require('cors');

const stripe = require('stripe')(process.env.PAYMENT_GATEWAY_KEY);

const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
// //load environment variables from .env file
// dotenv.config()
// const stripe = require('stripe') (process.env.PAYMENT_GATEWAY_KEY)


const port = process.env.PORT || 5000;


/***Middleware ****** */
app.use(cors());
app.use(express.json());

// for fb token, firbase SDK initialization 

const serviceAccount = require("./newleaf-firebase-admin-sdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});


/******start: MongoDB********************** */
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.3h4lqut.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();


/******************Playing field ******************** */
const usersCollection = client.db('newLeafDB').collection('users');
const policiesCollection = client.db("newLeafDB").collection("policies");
const applicationsCollection = client.db("newLeafDB").collection("applications");
const reviewsCollection = client.db("newLeafDB").collection("reviews");
const claimsCollection = client.db("newLeafDB").collection("claims");
const blogsCollection = client.db("newLeafDB").collection("blogs");
const newsletterCollection = client.db("newLeafDB").collection("newsletter");






/***Verify Firebase Token */
const verifyFBToken = async (req, res, next)=>{
// console.log('header in middleware', req.headers)
  const authHeader= req.headers.authorization;
  if(!authHeader){
    return res.status(401).send({message: 'unauthorized access!'})
  }
const token = authHeader.split(' ')[1];
if(!token){
  return res.status(401).send({message: 'unauthorized access'})
}

try{
  const decoded = await admin.auth().verifyIdToken(token);

// Fetch user role from DB
    const userDoc = await usersCollection.findOne({ email: decoded.email });
    decoded.role = userDoc?.role || 'user'; // fallback to 'user'

  req.decoded = decoded;
  next();
}catch(error){
  return res.status(403).send({message: 'forbidden access'})
}
}
/**End: verifyFbTOken */

/******verify Admin ******/
const verifyAdmin = async (req, res, next)=>{
  const email = req.decoded?.email;
  const query = {email};
  const user = await usersCollection.findOne(query);
  if(!user || user.role !== 'admin'){
    return res.status(403).send({message: 'forbidden access, not an admin'})
  }
  next();
}
/**End Verify Admin */

/******verify Agent ******/
const verifyAgent = async (req, res, next) => {
  const email = req.decoded?.email;
  const query = { email };
  const user = await usersCollection.findOne(query);
  if (!user || user.role !== 'agent') {
    return res.status(403).send({ message: 'forbidden access, not an agent' });
  }
  next();
};
/**End Verify Agent */

/****Verify Agent and admin */
const verifyAgentOrAdmin = async (req, res, next) => {
  const email = req.decoded?.email;
  const user = await usersCollection.findOne({ email });

  if (!user || (user.role !== 'agent' && user.role !== 'admin')) {
    return res.status(403).send({ message: 'Forbidden access: not an agent or admin' });
  }

  next();
};


// Test route to confirm deployment from public repo
app.get("/test-repo", (req, res) => {
  res.send("This backend is using the public repo ✅");
});

/******Blogs, manage blogs************** */
app.post("/blogs", async (req, res) => {
  try {
    const blog = req.body;
    const result = await blogsCollection.insertOne(blog);
    res.send(result);
  } catch (error) {
    console.error("Error adding blog:", error);
    res.status(500).send({ error: "Failed to add blog" });
  }
});


app.get("/blogs", async (req, res) => {
  try {
    const { authorEmail } = req.query;
    const query = authorEmail ? { authorEmail } : {};
    const blogs = await blogsCollection.find(query).toArray();
    res.send(blogs);
  } catch (error) {
    console.error("Error fetching blogs:", error);
    res.status(500).send({ error: "Failed to fetch blogs" });
  }
});

// DELETE /blogs/:id
app.delete("/blogs/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await blogsCollection.deleteOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (error) {
    console.error("Error deleting blog:", error);
    res.status(500).send({ error: "Failed to delete blog" });
  }
});


// PATCH: update a blog


app.patch("/blogs/:id", async (req, res) => {
  try {
    const id = req.params.id;
    console.log("Blog ID:", id);

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({ error: "Invalid blog ID" });
    }

    const updatedBlog = req.body;
console.log("Updated Blog Data:", updatedBlog);

    const result = await blogsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedBlog }
    );

    res.send(result);
  } catch (error) {
    console.error("Error updating blog:", error);
    res.status(500).send({ error: "Failed to update blog" });
  }
});


// PATCH /blogs/:id/visit
app.patch("/blogs/:id/visit", async (req, res) => {
  const id = req.params.id;
  const result = await blogsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $inc: { totalVisit: 1 } }
  );
  res.send(result);
});



/**** */

/****Newsletter */
app.post("/newsletter", async (req, res) => {
  const { name, email } = req.body;

  if (!name || !email) return res.status(400).send({ message: "Name and email required" });

  // Check if already subscribed
  const existing = await newsletterCollection.findOne({ email });
  if (existing) return res.status(409).send({ message: "Already subscribed" });

  const result = await newsletterCollection.insertOne({ name, email, subscribedAt: new Date() });
  res.send(result);
});


/**** */


/**Create a new policy (Admin only) */
app.post("/policies", verifyFBToken, verifyAdmin, async (req, res) => {
  const policy = req.body;
   // Extract numeric value from basePremiumRate string
  const match = policy.basePremiumRate.match(/\d+/);
  policy.premiumRateValue = match ? parseInt(match[0], 10) : 0;

  policy.createdAt = new Date();
  const result = await policiesCollection.insertOne(policy);
  res.send(result);
});
/******* */


// Get all policies (Public, with optional pagination and category filter)
// app.get("/policies", async (req, res) => {
//   const { category, page = 1, limit = 9 } = req.query;
//   const query = category ? { category } : {};

//   const skip = (parseInt(page) - 1) * parseInt(limit);

//   const [policies, total] = await Promise.all([
//     policiesCollection.find(query).skip(skip).limit(parseInt(limit)).toArray(),
//     policiesCollection.countDocuments(query),
//   ]);

//   res.send({ policies, total });
// });


app.get("/policies", async (req, res) => {
  const { category, search, page = 1, limit = 9, sort } = req.query;

  const query = {};

  if (category && category !== "all") {
    query.category = category;
  }

  if (search) {
    const regex = new RegExp(search, "i");
    query.$or = [
      { title: regex },
      { shortDescription: regex },
      { category: regex },
    ];
  }

  const skip = (parseInt(page) - 1) * parseInt(limit);

  // Default sort by createdAt (newest first)
  let sortOption = { createdAt: -1 };

  if (sort === "asc") {
    sortOption = { premiumRateValue: 1 }; 
  } else if (sort === "desc") {
    sortOption = { premiumRateValue: -1 }; 
  }

  const total = await policiesCollection.countDocuments(query);
  const policies = await policiesCollection
    .find(query)
    .sort(sortOption)
    .skip(skip)
    .limit(parseInt(limit))
    .toArray();

  res.send({ total, policies });
});



// Get most popular policies (limit optional)
app.get("/policies/popular", async (req, res) => {
  const limit = parseInt(req.query.limit) || 6;
  const popularPolicies = await policiesCollection
    .find({})
    .sort({ purchase_count: -1 }) // assumes there's a `popularity` or `purchaseCount` field
    .limit(limit)
    .toArray();

  res.send(popularPolicies);
});




app.get("/policies/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await policiesCollection.findOne(query);
    if (!result) return res.status(404).send({ message: "Policy not found" });
    res.send(result);
  } catch (error) {
    console.error("Error fetching policy by ID:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

// Update a policy
app.patch("/policies/:id", verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updatedData = { ...req.body };
    delete updatedData._id;            
    updatedData.updatedAt = new Date();

    const result = await policiesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updatedData }
    );

    res.send(result);
  } catch (err) {
    console.error("PATCH /policies/:id error:", err);
    res.status(500).send({ message: err.message });
  }
});



// Delete a policy
app.delete("/policies/:id", verifyFBToken, verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const result = await policiesCollection.deleteOne({ _id: new ObjectId(id) });
  res.send(result);
});


/************** POST: Create or update user **************/
app.post('/users', async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await usersCollection.findOne({ email });

    if (existingUser) {
      // Update last login
      await usersCollection.updateOne(
        { email },
        {
          $set: {
            last_log_in: new Date().toISOString(),
          },
        }
      );

      return res.status(200).send({ message: 'User already exists', inserted: false });
    }

    const userDoc = {
      ...req.body,
      created_at: new Date().toISOString(),
      last_log_in: new Date().toISOString(),
      role: 'customer', // default role
    };

    const result = await usersCollection.insertOne(userDoc);
    res.send(result);
  } catch (err) {
    console.error('❌ Failed to save user:', err);
    res.status(500).send({ message: 'Server error' });
  }
});


app.patch('/users', async (req, res) => {
  const { email, name, photoURL } = req.body;
  if (!email) return res.status(400).send({ error: "Email is required" });

  const result = await usersCollection.updateOne(
    { email },
    { $set: { name, photoURL } }
  );

  res.send(result);
});


/****GET: User Role */
app.get('/users/:email/role', async (req, res) => {
  const email = req.params.email;
  const user = await usersCollection.findOne({ email });

  if (!user) {
    return res.status(404).send({ message: 'User not found' });
  }

  res.send({ role: user.role || 'customer' });
});

/******* */




 /***Admin: Manage Users */
app.get('/users', verifyFBToken, verifyAdmin, async (req, res) => {
  const users = await usersCollection.find().sort({ created_at: -1 }).toArray();
  res.send(users);
});

app.patch('/users/:id/promote-agent', verifyFBToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const result = await usersCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { role: 'agent' } }
  );
  res.send(result);
});

app.patch('/users/:id/demote-customer', verifyFBToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const result = await usersCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { role: 'customer' } }
  );
  res.send(result);
});

 /******* */


/***Apply for isurance policy ***/

app.post('/applications', async (req, res) => {
  try {
    const application = req.body;

    // Fetch policy title using policyId
    const policy = await policiesCollection.findOne({
      _id: new ObjectId(application.policyId),
    });

    // Attach title from the policy to the application
    application.policyTitle = policy?.title || 'Untitled';

    application.status = 'Pending'; // default status
    application.payment_status = 'Due'; // default payment status

    const result = await applicationsCollection.insertOne(application);
    res.send(result);
  } catch (error) {
    console.error('Application submission error:', error);
    res.status(500).send({ message: 'Failed to submit application' });
  }
});

/*****For Admin 1. manage Application  */
// GET all applications (admin)
app.get("/applications", verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    const result = await applicationsCollection.find().toArray();
    res.send(result);
  } catch (error) {
    console.error("Error fetching applications:", error);
    res.status(500).send({ message: "Failed to fetch applications" });
  }
});




// Agent route: Get applications assigned to this agent, filtered by status
app.get("/agent/applications", verifyFBToken, verifyAgent, async (req, res) => {
  try {
    const email = req.decoded.email;
    const status = req.query.status;

    const query = { assignedAgentEmail: email };
    if (status) {
      query.status = status;
    }

    const result = await applicationsCollection.find(query).toArray();
    res.send(result);
  } catch (error) {
    console.error("Error fetching agent applications:", error);
    res.status(500).send({ message: "Failed to fetch applications" });
  }
});

app.get('/users/agents', async (req, res) => {
  const agents = await usersCollection.find({ role: 'agent' }).toArray();
  res.send(agents);
});

// Assign agent (auto-assign or let admin choose agent in future)
app.patch('/applications/:id/assign-agent', verifyFBToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { agentId } = req.body;

  const filter = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: {
      assignedAgentId: agentId,
      status: 'Assigned',
    }
  };

  const result = await applicationsCollection.updateOne(filter, updateDoc);
  res.send(result);
});

//featured agents
app.get("/agents/featured", async (req, res) => {
  try {
    const agents = await usersCollection
      .find({ role: "agent" })
      .project({
        name: 1,
        photoURL: 1,
        email: 1,
        experience: 1,
        specialties: 1,
        phone: 1,
        location: 1,
      })
      .limit(3)
      .toArray();

    res.send(agents);
  } catch (err) {
    res.status(500).send({ error: "Failed to fetch agents" });
  }
});


// Admin: Reject application with feedback
app.patch('/applications/:id/reject', verifyFBToken, verifyAdmin, async (req, res) => {
  const { id } = req.params;
  const { feedback } = req.body;
  const filter = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: {
      status: 'Rejected',
      rejectionFeedback: feedback || ''
    }
  };
  const result = await applicationsCollection.updateOne(filter, updateDoc);
  res.send(result);
});



/******* Get all applications for a user by email/ Get applications by customer email*****/
app.get('/applications/user/:email', async (req, res) => {
  const email = req.params.email;

  try {
    const applications = await applicationsCollection.aggregate([
      { $match: { email } },
      {
        $lookup: {
          from: 'policies',
          let: { policyIdStr: '$policyId' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $eq: ['$_id', { $toObjectId: '$$policyIdStr' }]
                }
              }
            }
          ],
          as: 'policyData',
        }
      },
      { $unwind: { path: '$policyData', preserveNullAndEmptyArrays: true } },
    ]).toArray();

    res.send(applications);
  } catch (error) {
    console.error('Failed to fetch applications with policy:', error);
    res.status(500).send({ message: 'Server error' });
  }
});


//  GET approved applications by email
app.get("/applications/approved/:email", async (req, res) => {
  try {
    const email = req.params.email;
    const approvedApplications = await applicationsCollection
      .find({ email, status: "Approved" })
      .toArray();

    // Attach policy title for each approved application
    const applicationsWithPolicyTitles = await Promise.all(
      approvedApplications.map(async (application) => {
        const policy = await policiesCollection.findOne({ _id: new ObjectId(application.policyId) });
        return {
          ...application,
          policyTitle: policy?.title || "Untitled Policy",
        };
      })
    );

    res.send(applicationsWithPolicyTitles);
  } catch (error) {
    console.error("Error fetching approved applications:", error);
    res.status(500).send({ message: "Server error while fetching approved applications" });
  }
});

//get single application by id
app.get("/applications/id/:id", async (req, res) => {
  try {
    const id = req.params.id;

    console.log("Incoming ID:", id); // ✅ Check what's being received

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid application ID" });
    }

    const objectId = new ObjectId(id);

    const application = await applicationsCollection.findOne({ _id: objectId });

    console.log("Application from DB:", application); // ✅ Inspect output

    if (!application) {
      return res.status(404).json({ error: "Application not found" });
    }

    // Optional: You can fetch policy data if needed
    // const policy = await policiesCollection.findOne({ _id: new ObjectId(application.policyId) });

    return res.status(200).json(application);
  } catch (error) {
    console.error("GET /applications/:id error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});




/***For Agent Dashboard */

// 🔓 Public route to fetch single user by email (used by agent dashboard)
app.get('/users/email/:email', async (req, res) => {
  const email = req.params.email;
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(404).send({ message: 'User not found' });
  res.send(user);
});

app.get("/applications/assigned/:agentId", verifyFBToken, async (req, res) => {
  const agentId = req.params.agentId;
  const assigned = await applicationsCollection
    .find({ assignedAgentId: agentId }) // not email
    .toArray();
  res.send(assigned);
});

app.patch('/applications/:id/status', verifyFBToken, verifyAgentOrAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  const application = await applicationsCollection.findOne({ _id: new ObjectId(id) });
  if (!application) return res.status(404).send({ message: 'Application not found' });

  const updateResult = await applicationsCollection.updateOne(
    { _id: new ObjectId(id) },
    { $set: { status } }
  );

  // ✅ If status is approved, increment the policy purchase count
  if (status === "Approved") {
    await policiesCollection.updateOne(
      { _id: new ObjectId(application.policyId) },
      { $inc: { purchase_count: 1 } }
    );
  }

  res.send(updateResult);
});

 
/**** */


// POST /reviews
app.post('/reviews', async (req, res) => {
  try {
    const review = req.body;
    console.log("Received review data:", review); 

    const result = await reviewsCollection.insertOne(review);
    console.log(" Inserted review:", result);
    res.send(result);
  } catch (error) {
    console.error(" Review POST error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

//Get reviews for testimonial
app.get('/reviews', async (req, res) => {
  try {
    const result = await reviewsCollection.find().sort({ date: -1 }).limit(6).toArray(); // get latest 6 reviews
    res.send(result);
  } catch (error) {
    console.error("Review GET error:", error);
    res.status(500).send({ message: "Internal server error" });
  }
});

// Create a payment intent
app.post("/create-payment-intent", async (req, res) => {
  const { amount } = req.body;

  if (!amount) {
    return res.status(400).json({ error: "Amount is required" });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount, // in cents
      currency: "BDT",
      payment_method_types: ["card"],
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
    });
  } catch (error) {
    console.error("Stripe error:", error.message);
    res.status(500).json({ error: error.message });
  }
});


// Handle successful payment and update application
app.post('/payments', verifyFBToken, async (req, res) => {
  const { applicationId, email, amount, transactionId, paymentMethod } = req.body;

  try {
    // Save the payment in a new collection (optional, but good practice)
    const paymentData = {
      applicationId,
      email,
      amount,
      transactionId,
      paymentMethod,
      paidAt: new Date(),
    };

    const paymentsCollection = client.db("newLeafDB").collection("payments");
    const paymentResult = await paymentsCollection.insertOne(paymentData);

    // Update application status to "Paid"
    const updateResult = await applicationsCollection.updateOne(
      { _id: new ObjectId(applicationId) },
      { $set: { payment_status: 'Paid', transactionId, paidAt: new Date() } }
    );

    res.send({ insertedId: paymentResult.insertedId, updated: updateResult.modifiedCount });
  } catch (err) {
    console.error('Error handling payment:', err);
    res.status(500).send({ message: 'Failed to process payment' });
  }
});


//admin:manage transaction
app.get('/payments', verifyFBToken, verifyAdmin, async (req, res) => {
  try {
    const paymentsCollection = client.db("newLeafDB").collection("payments");
    const applicationsCollection = client.db("newLeafDB").collection("applications");
    const policiesCollection = client.db("newLeafDB").collection("policies");

    // Fetch all payments sorted by latest
    const payments = await paymentsCollection.find().sort({ paidAt: -1 }).toArray();

    // Get all unique application IDs from payments
    const applicationIds = payments.map(p => new ObjectId(p.applicationId));
    // Fetch corresponding applications
    const applications = await applicationsCollection.find({ _id: { $in: applicationIds } }).toArray();

    // Get all unique policy IDs from applications
    const policyIds = applications.map(a => new ObjectId(a.policyId));
    // Fetch corresponding policies
    const policies = await policiesCollection.find({ _id: { $in: policyIds } }).toArray();

    // Enrich payments with email, policy title, date, status
    const enrichedPayments = payments.map(payment => {
      const application = applications.find(app => app._id.toString() === payment.applicationId);
      const policy = policies.find(pol => pol._id.toString() === application?.policyId);

      return {
        transactionId: payment.transactionId,
        email: payment.email || application?.email || 'N/A',
        policyName: policy?.title || 'N/A',
        amount: payment.amount,
        paidAt: payment.paidAt,
        status: 'Success',  // Assuming payment stored means successful; else adjust logic
      };
    });

    res.send(enrichedPayments);
  } catch (error) {
    console.error('Error fetching payments:', error);
    res.status(500).send({ message: 'Failed to fetch payments' });
  }
});



//Claim policy
app.post('/claims', verifyFBToken, async (req, res) => {
   console.log("POST /claims hit"); // <-- add this
  const claim = req.body;
  claim.status = 'Pending'; // default
  claim.createdAt = new Date();
  const result = await claimsCollection.insertOne(claim);
  res.send(result);
});

// GET /claims?agentEmail=agent@g.com
app.get('/claims', verifyFBToken, verifyAgent, async (req, res) => {
  const agentEmail = req.query.agentEmail;

  const claims = await claimsCollection
    .find({ agentEmail }) // Or filter as needed
    .toArray();

  res.send(claims);
});


app.get('/claims/:email', verifyFBToken, async (req, res) => {
  const email = req.params.email;
  const result = await claimsCollection.find({ userEmail: email }).toArray();
  res.send(result);
});

 


/******************end: Playing field ******************** */
    
    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);
/*******end; MongoDB */

// Root Route
app.get('/', (req, res) => {
  res.send('Welcome to NewLeaf Server');
});

// Start Server
app.listen(port, () => {
  console.log(`NewLeaf Server running on port ${port}`);
});


