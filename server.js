import express from 'express';
import mongoose from 'mongoose';
import 'dotenv/config';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from 'firebase-admin';
import cloudinary from 'cloudinary';
import multer from 'multer';  // Import multer for file uploads
import fs from 'fs';          // Import fs to remove uploaded files
import User from './Schema/User.js'; 
import Blog from './Schema/Blog.js';
import Notification from './Schema/Notification.js';
import Comment from './Schema/Comment.js';
import path from 'path';

// Check for required environment variables
const requiredEnvVars = [
  'DB_LOCATION',
  'SECRET_ACCESS_KEY',
  'CLOUDINARY_CLOUD_NAME',
  'CLOUDINARY_API_KEY',
  'CLOUDINARY_API_SECRET',
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    console.error(`Missing required environment variable: ${varName}`);
    process.exit(1);
  }
});


// Initialize Firebase Admin
try {
  const serviceAccountKeyPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH;
  const serviceAccount = JSON.parse(fs.readFileSync(path.resolve(serviceAccountKeyPath), 'utf8'));

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });

  console.log('Firebase Admin Initialized');
} catch (error) {
  console.error('Error initializing Firebase Admin:', error);
  process.exit(1);
}

const server = express();
const PORT = process.env.PORT || 3000;

// Regular Expressions for Validation
const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

// Middleware
server.use(express.json());
server.use(cors());



// Initialize multer for file uploads
const upload = multer({ storage: multer.memoryStorage() }); // Temporary upload directory

// Connect to MongoDB
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
})
.then(() => console.log('Database connected successfully'))
.catch(err => {
  console.error('Database connection error:', err);
  process.exit(1);
});

// Configure Cloudinary
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Function to upload image to Cloudinary
const uploadImageToCloudinary = async (imageBuffer) => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.v2.uploader.upload_stream(
            {
                folder: 'mern_blog', // Specify your folder
                resource_type: 'image',
            },
            (error, result) => {
                if (error) {
                    console.error('Cloudinary Upload Error:', error);
                    return reject(new Error('Image upload failed'));
                }
                resolve(result.secure_url); // Resolve with the secure URL of the uploaded image
            }
        );

        // Write the buffer to the stream
        uploadStream.end(imageBuffer);
    });
};


// Upload image route in your server file
server.post('/get-upload-url', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const imageUrl = await uploadImageToCloudinary(req.file.buffer);
        res.status(200).json({ imageUrl }); // Ensure this matches the key you expect in the client
    } catch (err) {
        console.error('Error in /get-upload-url route:', err);
        res.status(500).json({ error: 'Internal server error', message: err.message });
    }
});



// JWT Verification Middleware
// const verifyJWT = (req, res, next) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(" ")[1];

//   if (!token) {
//     return res.status(401).json({ error: "No access token" });
//   }

//   jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
//     if (err) {
//       return res.status(403).json({ error: "Access token is invalid" });
//     }
//     req.user = user;
//     next();
//   });
// };

// Extract only the user ID from the JWT in your middleware (verifyJWT.js)
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  // Check if Authorization header is present
  if (!authHeader) {
    return res.status(401).json({ error: "No access token" });
  }

  // Extract the token from the Authorization header
  const token = authHeader.split(" ")[1];

  // If no token is found, return an error
  if (!token) {
    return res.status(401).json({ error: "No access token" });
  }

  // Verify the token
  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid" });
    }

    // Attach the user data (e.g., user ID) to the request object
    req.user = user.id; // Assuming the token contains `id` field for user identification
    next(); // Proceed to the next middleware
  });
};



// Helper Function to Format Data to Send
const formatDatatoSend = (user) => {
  const access_token = jwt.sign({ id: user._id, email: user.personal_info.email, admin: user.admin }, process.env.SECRET_ACCESS_KEY);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

// Helper function to generate a unique username
const generateUsername = async (email) => {
  let username = email.split("@")[0];
  let usernameExists = await User.exists({ "personal_info.username": username });
  if (usernameExists) {
    username += nanoid().substring(0, 5);
  }
  return username;
};

// Signup route
server.post('/signup', (req, res) => {
  const { fullname, email, password } = req.body;

  // Validating data from frontend
  if (fullname.length < 3) {
    return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
  }
  if (!email.length) {
    return res.status(403).json({ "error": "Enter Email" });
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ "error": "Email is invalid" });
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    if (err) {
      return res.status(500).json({ "error": "Error hashing password" });
    }

    const username = await generateUsername(email);
    const user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_password,
        username
      }
    });

    user.save()
      .then((u) => res.status(200).json(formatDatatoSend(u)))
      .catch(err => {
        if (err.code === 11000) {
          return res.status(500).json({ "error": "Email already exists" });
        }
        return res.status(500).json({ "error": err.message });
      });
  });
});

// Signin route
server.post("/signin", (req, res) => {
  const { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ "error": "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(403).json({ "error": "Error occurred while logging in, please try again" });
          }
          if (!result) {
            return res.status(403).json({ "error": "Incorrect password" });
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      } else {
        return res.status(403).json({ "error": "Account was created using Google. Try logging in with Google." });
      }
    })
    .catch(err => res.status(500).json({ "error": "Server error" }));
});

// Google Signin route
server.post("/google-signin", async (req, res) => {
  const { email, fullname, googleId } = req.body;

  try {
    let user = await User.findOne({ "personal_info.email": email });

    if (user) {
      return res.status(200).json(formatDatatoSend(user));
    } else {
      const username = await generateUsername(email);
      user = new User({
        personal_info: {
          fullname,
          email,
          username,
          googleId,
        },
      });
      await user.save();
      return res.status(200).json(formatDatatoSend(user));
    }
  } catch (err) {
    return res.status(500).json({ "error": err.message });
  }
});

server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodeUser) => {
      let { email, name, picture } = decodeUser;
      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u) => {
        return u || null;
      })
        .catch(err => {
          return res.status(500).json({ "error": err.message });
        });

      if (user) { // login
        if (!user.google_auth) {
          return res.status(403).json({ "error": "This email was signed up without Google. Please log in with a password to access the account" });
        }
      }
      else {
        let username = await generateUsername(email);

        user = new User({
          personal_info: { fullname: name, email, profile_img: picture, username },
          google_auth: true
        });

        await user.save().then((u) => {
          user = u;
        })
          .catch(err => {
            return res.status(500).json({ "error": err.message });
          });
      }
      return res.status(200).json(formatDatatoSend(user));
    })
    .catch(err => {
      return res.status(500).json({ "error": "Failed to authenticate you with Google. Try with some other Google account" });
    });
});

server.post("/change-password", verifyJWT, (req, res) => {

  let { currentPassword, newPassword } = req.body;

  if(!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)){
            return res.status(403).json({ "error": "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" });
        }

        User.findOne({ _id: req.user })
        .then((user) => {

          if(user.google_auth){
            return res.status(403).json({ error: "You can't change account's password because you logged in through google" })
          }

          bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
            if(err){
              return res.status(500).json({ error: "Some error occured while changing the password, please try again later" })
            }

            if(!result){
              return res.status(403).json({ error: "Incorrect current password" })
            }

            bcrypt.hash(newPassword, 10, (err, hashed_password) => {

              User.findOneAndUpdate({_id: req.user}, {"personal_info.password": hashed_password})
              .then((u) => {
                return res.status(200).json({ status: 'password changed' })
              })
              .catch(err => {
                return res.status(500).json({ error: 'Some error ocurred while saving new password, please try again latter' })
              })

            })
          })
          .catch(err => {
            console.log(err);
            res.status(500).json({ error: "User not found" })
          })

        })

})

server.post('/latest-blogs', (req, res) => {

  let { page } = req.body;

  let maxLimit = 5;

  Blog.find({ draft: false, is_approved:true, })
  .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({ "publishedAt": -1 })
  .select("blog_id title des banner activity tags publishedAt -_id")
  .skip((page - 1) * maxLimit)
  .limit(maxLimit)
  .then(blogs => {
    return res.status(200).json({ blogs })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})

server.post('/all-latest-blogs-count', (req, res) => {



  Blog.countDocuments({ draft: false, is_approved:true, })
  .then(count => {
    return res.status(200).json({ totalDocs: count })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})

server.get('/trending-blogs', (req, res) => {
  const maxLimit = 5; // Max number of blogs to return

  Blog.find({ draft: false, is_approved:true })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname") 
    .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 })
    .select("blog_id title des banner publishedAt activity.total_likes") 
    .limit(maxLimit)
    .then(blogs => {
      res.status(200).json({ blogs });
    })
    .catch(err => {
      console.error('Error fetching trending blogs:', err.message);
      res.status(500).json({ error: "Failed to fetch trending blogs" });
    });
});


server.post('/search-blogs', (req, res) => {

  let { tag, query, author,  page, limit, eliminate_blog } = req.body;

  let findQuery;

  if(tag) {
    findQuery = { tags: tag,  draft: false, is_approved:true, blog_id: { $ne: eliminate_blog} };
  } else if(query) {
    findQuery = { draft: false, title: new RegExp(query, 'i') }
  } else if(author) {
    findQuery = { author, draft: false }
  }

  let maxLimit = limit ? limit : 2;

  Blog.find(findQuery)
  .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({ "publishedAt": -1 })
  .select("blog_id title des banner activity tags publishedAt -_id")
  .skip((page - 1 ) * maxLimit)
  .limit(maxLimit)
  .then(blogs => {
    return res.status(200).json({ blogs })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})


server.post('/search-blogs-count', (req, res) => {

  let { tag, author, query } = req.body;

  let findQuery;

  if(tag) {
    findQuery = { tags: tag,  draft: false, is_approved:true, };
  } else if(query) {
    findQuery = { draft: false, title: new RegExp(query, 'i') }
  } else if(author) {
    findQuery = { author, draft: false }
  }



  Blog.countDocuments(findQuery)
  .then(count => {
    return res.status(200).json({ totalDocs: count })
  })
  .catch(err => {
    console.log(err.message)
    return res.status(500).json({ error: err.message })
  })

})

server.post("/search-user", (req, res) => {
    let { query } = req.body;

    User.find({ "personal_info.username": new RegExp(query, 'i') })
    .limit(50)
    .select(" personal_info.fullname personal_info.username personal_info.profile_img -_id")
    .then(users => {
      return res.status(200).json({ users })
    })
    .catch(err => {
    return res.status(500).json({ error: err.message })
  })
})

server.post("/get-profile", (req, res) => {
  let { username } = req.body;

  User.findOne({"personal_info.username": username })
  .select("-personal_info.password -google_auth -updateAt -blogs")
  .then(user => {
    return res.status(200).json(user)
  })
  .catch(err => {
    console.log(err)
    return res.status(500).json({ error: err.message })
  })
})

server.post("/update-profile-img", verifyJWT , (req, res) => {

  let { url } = req.body;

  User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img":  url })
  .then(() => {
    return res.status(200).json({ profile_img: url })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})

server.post("/update-profile", verifyJWT, (req, res) => {

  let { username, bio, social_links } = req.body;

  let bioLimit = 150

  if(username.length < 3){
    return res.status(403).json({ error: `Username should not bbe  more than ${bioLimit}` })
  }
  if(bio.length > bioLimit ){
    return res.status(403).json({ error: `Username should not bbe  more than ${bioLimit}` })
  }

  let socialLinksArr = Object.keys(social_links)

  try {
    for(let i = 0; i < socialLinksArr.length; i++){
      if(social_links[socialLinksArr[i]].length){
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if(!hostname.includes(`${socialLinksArr[i]}.com` ) && socialLinksArr[i] != 'website'){
          return res.status(403).json({ error: `${socialLinksArr[i]} link is invalid. You must enter a full link` })
        }
      }
    }
  } catch (err) {
    return res.status(500).json({ error: `You must provide full social links with http's include` })
  }

  let updateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links
  }

  User.findOneAndUpdate({ _id: req.user }, updateObj, {
    runValidators: true
  })
  .then(() => {
    return res.status(200).json({ username })
  })
  .catch(err => {
    if(err.code == 1100){
      return res.status(409).json({ error: "username is already token" })
    }
    return res.status(500).json({ error: err.message })
  })

})

server.post("/create-blog", verifyJWT, (req, res) => {
  const authorId = req.user;  // req.user is now just the user ID string

  let { title, des, banner, tags, content, draft, id } = req.body;

  if (!title || !title.length) {
    return res.status(403).json({ error: "You must provide a title" });
  }

  if (!draft) {
    if (!des || des.length > 200) {
      return res.status(403).json({ error: "You must provide a blog description under 200 characters" });
    }
    if (!banner || !banner.length) {
      return res.status(403).json({ error: "You must provide a blog banner to publish it" });
    }
    if (!content || !content.blocks || !content.blocks.length) {
      return res.status(403).json({ error: "There must be some blog content to publish it" });
    }
    if (!tags || !tags.length || tags.length > 10) {
      return res.status(403).json({ error: "Provide tags in order to publish the blog, Maximum 10" });
    }
  }

  tags = tags.map(tag => tag.toLowerCase());

  const blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();

  const blogData = {
    title,
    des,
    banner,
    content,
    tags,
    author: authorId,  // Now using the correct ObjectId
    blog_id,
    draft: Boolean(draft)
  };

  if (id) {
    Blog.findOneAndUpdate({ blog_id }, blogData, { new: true })
      .then(updatedBlog => {
        if (!updatedBlog) {
          return res.status(404).json({ error: "Blog not found" });
        }
        return res.status(200).json({ id: blog_id });
      })
      .catch(err => {
        console.error('Error updating blog:', err);
        return res.status(500).json({ error: "An error occurred while updating the blog" });
      });
  } else {
    const blog = new Blog(blogData);

    blog.save()
      .then(newBlog => {
        const incrementalVal = draft ? 0 : 1;

        return User.findOneAndUpdate(
          { _id: authorId },
          { $inc: { "account_info.total_posts": incrementalVal }, $push: { "blogs": newBlog._id } }
        )
          .then(() => {
            res.status(200).json({ id: newBlog.blog_id });
          })
          .catch(err => {
            console.error('Error updating user after saving blog:', err);
            res.status(500).json({ error: "An error occurred while updating the user" });
          });
      })
      .catch(err => {
        console.error('Error saving blog:', err);
        res.status(500).json({ error: "An error occurred while saving the blog" });
      });
  }
});


// server.post("/create-blog", verifyJWT, (req, res) => {
//   const authorId = req.user;

 

//     let { title, des, banner, tags, content, draft, id } = req.body;

//   if (!title || !title.length) {
//     return res.status(403).json({ error: "You must provide a title" });
//   }

//   if (!draft) {
//     if (!des || des.length > 200) {
//       return res.status(403).json({ error: "You must provide a blog description under 200 characters" });
//     }
//     if (!banner || !banner.length) {
//       return res.status(403).json({ error: "You must provide a blog banner to publish it" });
//     }
//     if (!content || !content.blocks || !content.blocks.length) {
//       return res.status(403).json({ error: "There must be some blog content to publish it" });
//     }
//     if (!tags || !tags.length || tags.length > 10) {
//       return res.status(403).json({ error: "Provide tags in order to publish the blog, Maximum 10" });
//     }
//   }

//   tags = tags.map(tag => tag.toLowerCase());
//   const blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-").trim() + nanoid();

//   const blog = new Blog({
//     title, des, banner, content, tags, author: authorId, blog_id, draft: Boolean(draft)
//   });

//   if(id) {

//     Blog.findOneAndUpdate({ blog_id }, { title, des, banner, content, tags, draft: draft ? draft : false })
//     .then(() => {
//       return res.status(200).json({ id: blog_id });
//     })
//     .catch(err => {
//       res.status(500).json({ error: err.message });
//     });

//   } else {
//     blog.save().then(blog => {
//     const incrementalVal = draft ? 0 : 1;

//     return User.findOneAndUpdate(
//       { _id: authorId },
//       { $inc: { "account_info.total_posts": incrementalVal }, $push: { "blogs": blog._id } }
//     )
//       .then(user => {
//         res.status(200).json({ id: blog.blog_id });
//       });
//   })
//     .catch(err => {
//       res.status(500).json({ error: err.message });
//     });
//   }
// });

server.post("/get-blog", (req, res) => {

  let { blog_id, draft, mode } = req.body;

  let incrementVal = mode != 'edit' ? 1 : 0;

  Blog.findOneAndUpdate({ blog_id }, { $inc : { "activity.total_reads": incrementVal } })
  .populate("author", "personal_info.fullname personal_info.username personal_info.profile_img")
  .select("title des content banner activity publishedAt blog_id tags")
  .then(blog => {

    User.findOneAndUpdate({"personal_info.username": blog.author.personal_info.username }, {
       $inc : { "account_info.total_reads": incrementVal }
    })
    .catch(err => {
    return res.status(500).json({ error: err.message })
  })


    if(blog.draft && !draft) {
      return res.status(500).json({ error: 'you can not access draft blogs' })
    }

    return res.status(200).json({ blog });
  })

})

server.post("/like-blog", verifyJWT, (req, res) => {
   
  let user_id = req.user;

  let { _id, islikedByUser } = req.body;

  let incrementVal = !islikedByUser ? 1 : 0;

  Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal }} )
  .then(blog => {

    if(!islikedByUser){
      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id
      })

      like.save().then(notification => {
          return res.status(200).json({ liked_by_user: true })
      })
    } else {
      Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like"})
      .then(data => {
        return res.status(200).json({ liked_by_user: false })
      })
      .catch(err => {
    return res.status(500).json({ error: err.message })
  })
    }

  })

})

server.post("/isliked-by-user", verifyJWT, (req, res) => {

  let user_id  = req.user;

  let  { _id  } = req.body;

  Notification.exists({ user: user_id, type: "like", blog: _id })
  .then(result => {
    return res.status(200).json({ result })

  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })
})

server.post("/add-comment", verifyJWT , (req, res) => {
  let user_id = req.user;
  let { _id, comment, replying_to, blog_author, notification_id } = req.body;

  if (!comment.length) {
    return res.status(403).json({ error: "Write something to leave a comment" });
  }

  // Creating the comment object, and handling parent (reply) if necessary
  let commentObj = {
    blog_id: _id, 
    blog_author, 
    comment, 
    commented_by: user_id
  };

  if (replying_to) {
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }

  new Comment(commentObj).save().then(async commentFile => {
    let { comment, commentedAt, children } = commentFile;

    // Update the blog's comment count
    Blog.findOneAndUpdate(
      { _id }, 
      { 
        $push: { "comments": commentFile._id }, 
        $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 }  
      }
    ).then(() => {
      console.log("New comment created");
    });

    // Create notification object
    let notificationObj = {
      type: replying_to ? "reply" : "comment",
      blog: _id,
      notification_for: blog_author,
      user: user_id,
      comment: commentFile._id
    };

    if (replying_to) {
      notificationObj.replied_on_comment = replying_to;


      let replyingToCommentDoc = await Comment.findOneAndUpdate(
        { _id: replying_to },
        { $push: { children: commentFile._id } }, 
        { new: true }
      );

      if(notification_id){
        Notification.findOneAndUpdate({ _id: notification_id }, { reply: commentFile._id })
        .then(notification => console.log('notification updated'))
      }


      notificationObj.notification_for = replyingToCommentDoc.commented_by;
    }

    // Save the notification
    new Notification(notificationObj).save().then(() => {
      console.log('New notification created');
    });

    return res.status(200).json({
      comment, 
      commentedAt, 
      _id: commentFile._id, 
      user_id, 
      children
    });
  }).catch(err => {
    return res.status(500).json({ error: err.message });
  });
});


 server.post("/get-blog-comments", (req, res) => {

  let { blog_id, skip } = req.body;

  let maxLimit = 5;

  Comment.find({ blog_id, isReply: false })
  .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
  .skip(skip)
  .limit(maxLimit)
  .sort({
    'commentedAt': -1
  })
  .then(comment => {
    return res.status(200).json(comment);
  })
  .catch(err => {
    console.log(err.message);
    return res.status(500).json({ error: err.message })
  })

 })

 server.post("/get-replies", (req, res) => {
  let { _id, skip } = req.body;
  let maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",   
      options: { 
        limit: maxLimit,
        skip: skip,
        sort: { 'commentedAt': -1 }  
      },
      populate: {
        path: 'commented_by',
        select: "personal_info.profile_img personal_info.fullname personal_info.username"
      },
      select: "-blog_id -updatedAt"  
    })
    .select("children")  
    .then(doc => {
      console.log('Replies fetched successfully:', doc);
      return res.status(200).json({ replies: doc.children });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
});


const deleteComments = (_id) => {
  Comment.findOneAndDelete({ _id })
  .then(comment => {

    if (comment.parent) {

      Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
        .then(() => console.log('comment deleted from parent'))
        .catch(err => console.log(err));
    }

    // Deleting related notifications
    Notification.findOneAndDelete({ comment: _id }).then(() => console.log('comment notification deleted'));
    Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(() => console.log('reply notification deleted'));

    // Updating blog's comments and activity count
    Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1, "activity.total_parent_comments": comment.parent ? 0 : -1 } })
      .then(blog => {
        // If comment has replies (children), recursively delete them
        if (comment.children.length) {
          comment.children.map(replies => {
            deleteComments(replies);
          });
        }
      })
      .catch(err => console.log(err.message));
  });
};


server.post("/delete-comment", verifyJWT, (req, res) => {
  let user_id = req.user;  // Get authenticated user
  let { _id } = req.body;  // Comment ID to be deleted

  Comment.findOne({ _id }).then(comment => {
    if (user_id == comment.commented_by || user_id == comment.blog_author) {
      deleteComments(_id);  // Recursive deletion
      return res.status(200).json({ status: 'done' });
    } else {
      return res.status(403).json({ error: "You cannot delete this comment" });
    }
  });
});


server.get("/new-notification", verifyJWT, (req, res) => {

  let user_id = req.user;

  Notification.exists({ notification_for: user_id, seen: false, user: {$ne: user_id} })
  .then(result => {
    if( result ){
      return res.status(200).json({ new_notification_available: true })
    } else{
      return res.status(200).json({ new_notification_available: false })
    }
  })

})

server.post("/notifications", verifyJWT, (req, res) => {
  let user_id = req.user;

  let  { page, filter, deleteDocCount } = req.body;

  let maxLimit = 10;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };

  let skipDocs = (page - 1) * maxLimit;

  if(filter != 'all'){
    findQuery.type = filter;
  }

  if(deleteDocCount){
    skipDocs -= deleteDocCount;
  }

  Notification.find(findQuery)
  .skip(skipDocs)
  .limit(maxLimit)
  .populate("blog", "title blog_id")
  .populate("user", "personal_info.fullname personal_info.username personal_info.profile_img")
  .populate("comment", "comment")
  .populate("replied_on_comment", "comment")
  .populate("reply", "comment")
  .sort({ createdAt: -1 })
  .select("createdAt type seen reply")
  .then(notifications => {

    Notification.updateMany(findQuery, { seen: true })
    .skip(skipDocs)
    .limit(maxLimit)
    .then(() => console.log('notification seen'))

    return res.status(200).json({ notifications })


  })
  .catch(err => {
    console.log(err.message)
      return res.status(500).json({ error: err.message });
    });
})

server.post("/all-notifications-count", verifyJWT, (req, res) => {
  let user_id = req.id;

  let  {  filter } = req.body;


  let findQuery = { notification_for: user_id, user: { $ne: user_id } };


  if(filter != 'all'){
    findQuery.type = filter;
  }


  Notification.countDocuments(findQuery)
  .then(count => {

    return res.status(200).json({ totalDocs: count })

  })
  .catch(err => {
    console.log(err.message)
      return res.status(500).json({ error: err.message });
    });
})

server.post("/user-written-blogs", verifyJWT, (req, res) => {

  let user_id = req.user;

  let { page, draft, query, deleteDocCount } = req.body;

  let maxLimit = 5;

  let skipDocs = (page - 1) * maxLimit;

  if(deleteDocCount){
    skipDocs -= deleteDocCount;
  }

  Blog.find({ author: user_id, draft, title: new RegExp(query, 'i') })
  .skip(skipDocs)
  .limit(maxLimit)
  .sort({ publishedAt: -1 })
  .select(" title banner publishedAt blog_id activity des draft  -_id ")
  .then(blogs => {
    return res.status(200).json({ blogs })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })
})

server.post("/user-written-blogs-count", verifyJWT, (req, res) => {
  let user_id = req.user;

  let { draft, query } = req.body

  Blog.countDocuments({ author: user_id, draft, title: new RegExp(query, 'i') })
  .then(count => {
    return res.status(200).json({ totalDocs: count })
  })
  .catch(err => {
    console.log(err.message);
    return res.status(500).json({ error: err.message })
  })
})

server.post("/delete-blog", verifyJWT, (req, res) => {

  let user_id = req.user;
  let { blog_id } = req.body;


     Blog.findOneAndDelete({ blog_id })
  .then(blog => {

    Notification.deleteMany({ blog: blog._id })
    .then(data => console.log('notifications deleted'));

    Comment.deleteMany({ blog_id: blog._id })
    .then(data => console.log('comments deleted'));

    User.findOneAndUpdate({ _id: user_id }, { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } })
    .then(user => console.log('Blog deleted'));

    return res.status(200).json({ status: 'done' })

  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})


// admin section start

// **************
server.post("/admin-signin", async (req, res) => {
  const { email, password } = req.body;


  try {
    const user = await User.findOne({ "personal_info.email": email  });


    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }


    // Check if the user is an admin
    if (!user.admin) {
      return res.status(403).json({ error: "Access denied: Admins only" });
    }

    // Compare the password
    bcrypt.compare(password,user.personal_info.password, (err,result)=>{
       if (err) {
            return res.status(403).json({ "error": "Error occurred while logging in, please try again" });
          }
      if (!result) {
            return res.status(401).json({ "error": "Incorrect password" });
     }else{
      return res.status(200).json(formatDatatoSend(user));
     }
    }) 

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});



// Dashboard Overview

server.get('/all-likes', async (req, res) => {
    try {
        // Fetch notifications where type is 'like'
        const notifications = await Notification.find({ type: 'like',  })
            .populate('user', 'username email') // Populate user fields
            .exec(); // Ensure the query is executed

        // Map to extract likes details
        const likesDetails = notifications.map(notification => ({
            user: notification.user,
            blog: notification.blog, // Assuming you have a blog reference here
            createdAt: notification.createdAt // Add more fields as needed
        }));

        res.status(200).json(likesDetails); // Use json to send data as JSON response
    } catch (error) {
        console.error('Error fetching likes:', error);
        res.status(500).send({ message: 'Failed to fetch likes' });
    }
});


server.get('/all-comments', async (req, res) => {
    try {
        // Fetch notifications where type is 'like'
        const notifications = await Notification.find({ type: 'comment',  })
            .populate('user', 'username email') // Populate user fields
            .exec(); // Ensure the query is executed

        // Map to extract likes details
        const commentsDetails = notifications.map(notification => ({
            user: notification.user,
            blog: notification.blog, // Assuming you have a blog reference here
            createdAt: notification.createdAt // Add more fields as needed
        }));

        res.status(200).json(commentsDetails); // Use json to send data as JSON response
    } catch (error) {
        console.error('Error fetching likes:', error);
        res.status(500).send({ message: 'Failed to fetch likes' });
    }
});

server.get('/all-blog-count', async (req, res) => {
  try {
    // Count all blogs in the Blog collection
    const blogCount = await Blog.countDocuments(); // Using countDocuments to get the total number of documents

    res.status(200).send({ totalBlogs: blogCount }); // Send the count as a response
  } catch (error) {
    console.error('Error fetching blog count:', error);
    res.status(500).send({ message: 'Failed to fetch blog count' });
  }
});


server.get('/all-users-count', async (req, res) => {
  try {
    // Count all users in the User collection
    const usersCount = await User.countDocuments(); // Using countDocuments to get the total number of users

    res.status(200).send({ totalUsers: usersCount }); // Send the count as a response
  } catch (error) {
    console.error('Error fetching users count:', error); // Corrected error message
    res.status(500).send({ message: 'Failed to fetch users count' }); // Corrected response message
  }
});

// Fetch all users, including email and role
server.get('/all-users', async (req, res) => {
  try {
    const users = await User.find({}, 'personal_info.email personal_info.role personal_info.username'); // Select necessary fields
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).send({ message: 'Failed to fetch users' });
  }
});


// DELETE route to handle user deletion
server.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params; // Get the user ID from the URL params
    const deletedUser = await User.findByIdAndDelete(userId); // Delete the user by ID

    if (!deletedUser) {
      return res.status(404).send({ message: 'User not found' });
    }

    res.status(200).send({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).send({ message: 'Failed to delete user' });
  }
});


server.get('/all-blogs-comment', async (req, res) => {
  try {
    const blogs = await Blog.find()
      .populate("author", "personal_info.fullname personal_info.profile_img") // Populating fullname and profile image
      .select("title author"); // Select necessary fields, including title and author

    res.status(200).json(blogs); // Send the populated blogs
  } catch (error) {
    console.error('Error fetching blogs:', error);
    res.status(500).send({ message: 'Failed to fetch blogs' });
  }
});

server.post("/admin-show-comments", (req, res) => {
  const { blog_id, skip } = req.body;
  const maxLimit = 5;

  if (!blog_id) {
    return res.status(400).json({ error: "Blog ID is required" });
  }

  Comment.find({ blog_id })
    .populate("commented_by", "personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({ commentedAt: -1 })
    .then((comments) => {
      res.status(200).json(comments);
    })
    .catch((err) => {
      console.error("Error fetching comments:", err.message);
      res.status(500).json({ error: err.message });
    });
});
;


 server.post("/admin-get-replies", (req, res) => {
  let { _id, skip } = req.body;
  let maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",   
      options: { 
        limit: maxLimit,
        skip: skip,
        sort: { 'commentedAt': -1 }  
      },
      populate: {
        path: 'commented_by',
        select: "personal_info.profile_img personal_info.fullname personal_info.username"
      },
      select: "-blog_id -updatedAt"  
    })
    .select("children")  
    .then(doc => {
      console.log('Replies fetched successfully:', doc);
      return res.status(200).json({ replies: doc.children });
    })
    .catch(err => {
      return res.status(500).json({ error: err.message });
    });
});


const adminDeleteComments = (_id) => {
  Comment.findOneAndDelete({ _id })
  .then(comment => {

    if (comment.parent) {

      Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
        .then(() => console.log('comment deleted from parent'))
        .catch(err => console.log(err));
    }

    // Deleting related notifications
    Notification.findOneAndDelete({ comment: _id }).then(() => console.log('comment notification deleted'));
    Notification.findOneAndUpdate({ reply: _id }, { $unset: { reply: 1 } }).then(() => console.log('reply notification deleted'));

    // Updating blog's comments and activity count
    Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1, "activity.total_parent_comments": comment.parent ? 0 : -1 } })
      .then(blog => {
        // If comment has replies (children), recursively delete them
        if (comment.children.length) {
          comment.children.map(replies => {
            deleteComments(replies);
          });
        }
      })
      .catch(err => console.log(err.message));
  });
};


server.post('/admin-all-blogs', (req, res) => {

  let { page } = req.body;

  let maxLimit = 5;

  Blog.find({ draft: false })
  .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
  .sort({ "publishedAt": -1 })
  .select("blog_id title des banner activity tags publishedAt -_id")
  .skip((page - 1) * maxLimit)
  .limit(maxLimit)
  .then(blogs => {
    return res.status(200).json({ blogs })
  })
  .catch(err => {
    return res.status(500).json({ error: err.message })
  })

})

// const verifyToken = (req, res, next) => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) {
//     return res.status(401).json({ error: 'No access token' });
//   }

//   jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
//     if (err) {
//       return res.status(403).json({ error: 'Token is invalid' });
//     }

//     console.log('Decoded user from token:', user); // Check if `admin` is present here
//     req.user = user;
//     next();
//   });
// };


// // Middleware to check if the user is an admin
// const isAdmin = (req, res, next) => {
//   const user = req.user;

//   // Ensure the `admin` field is a boolean
//   console.log('Admin check:', user.admin === true, typeof user.admin); // Log the type for debugging

//   if (user && user.admin === true) {
//     console.log('Admin access granted');
//     next();
//   } else {
//     console.log('Admin access denied');
//     return res.status(403).json({ error: 'Access denied. Admins only.' });
//   }
// };



// Route to delete a blog (admin-only access)

server.delete('/blog/:blogId', async (req, res) => {
  try {
    const { blogId } = req.params; 

    // Check if blogId is a valid ObjectId, if not, search using blog_id field
    let deletedBlog;
    if (mongoose.Types.ObjectId.isValid(blogId)) {
      deletedBlog = await Blog.findByIdAndDelete(blogId); // Search by _id (MongoDB ObjectId)
    } else {
      deletedBlog = await Blog.findOneAndDelete({ blog_id: blogId }); // Search by custom blog_id field
    }

    if (!deletedBlog) {
      return res.status(404).send({ message: 'Blog not found' });
    }

    res.status(200).send({ message: 'Blog deleted successfully' });
  } catch (error) {
    console.error('Error deleting blog:', error);
    res.status(500).send({ message: 'Failed to delete blog' });
  }
});

server.put('/blog/approve/:blogId', async (req, res) => {
  try {
    const { blogId } = req.params;  // Extract blog ID from the URL
    const updatedBlog = await Blog.findOneAndUpdate(
      { blog_id: blogId },  // Use blog_id for the query
      { is_approved: true }, // Set `is_approved` to true
      { new: true } // Return the updated document
    );

    if (!updatedBlog) {
      return res.status(404).send({ message: 'Blog not found' });
    }

    res.status(200).send({ message: 'Blog approved successfully', blog: updatedBlog });
  } catch (error) {
    console.error('Error approving blog:', error);
    res.status(500).send({ message: 'Failed to approve blog' });
  }
});



// Start the server
server.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
