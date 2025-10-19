import { generateToken } from "../lib/utils.js";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";

// ✅ Signup a new user
export const signup = async (req, res) => {
  const { fullName, email, password, bio } = req.body;

  try {
    if (!fullName || !email || !password || !bio) {
      return res
        .status(400)
        .json({ success: false, message: "Missing details" });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(409)
        .json({ success: false, message: "Account already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      fullName,
      email,
      password: hashedPassword,
      bio,
    });

    const token = generateToken(newUser._id);

    const { password: _, ...userData } = newUser._doc;

    res.status(201).json({
      success: true,
      userData,
      token,
      message: "Account created successfully",
    });
  } catch (error) {
    console.error("Signup Error:", error.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ✅ Login a user
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input check
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }

    const token = generateToken(user._id);

    const { password: _, ...userData } = user._doc;

    res.status(200).json({
      success: true,
      userData,
      token,
      message: "Login successful",
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ✅ Check if user is authenticated
export const checkAuth = (req, res) => {
  res.status(200).json({ success: true, user: req.user });
};

// ✅ Update user profile
export const updateProfile = async (req, res) => {
  try {
    const { profilePic, bio, fullName } = req.body;
    const userId = req.user._id;

    let updateData = { bio, fullName };

    if (profilePic) {
      const upload = await cloudinary.uploader.upload(profilePic);
      updateData.profilePic = upload.secure_url;
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
    }).select("-password"); // Don’t return password

    res.status(200).json({ success: true, user: updatedUser });
  } catch (error) {
    console.error("Profile Update Error:", error.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
