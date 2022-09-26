const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

//@desc Register new user
//@route POST /api/user
//@access PUBLIC
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, phone } = req.body;

  if (!name || !email || !password) {
    res.status(400);
    throw new Error("Add all fields");
  }

  //Check if user exists
  const UserExists = await User.findOne({ email });

  if (UserExists) {
    res.status(400);
    throw new Error("User already exists");
  }

  //Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  //Create the user
  const user = await User.create({
    email,
    name,
    password: hashedPassword,
  });

  if (user) {
    res.status(201).json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

//@desc Login user
//@route POST /api/user/login
//@access PUBLIC
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  //Check if user exists
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    });
  } else {
    res.status(400);
    throw new Error("Password or Email is incorrect");
  }
});

//@desc Get user data
//@route GET /api/user/me
//@access PRIVATE
const getMe = asyncHandler(async (req, res) => {
  const {_id,name,email} = await User.findById(req.user.id)
  res.status(200).json({
    id: _id,
    name,
    email
  })
});

//Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });
};

module.exports = {
  registerUser,
  loginUser,
  getMe,
};
