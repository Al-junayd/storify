import { redis } from "../lib/redis.js";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });
  return { accessToken, refreshToken };
};

const storeRefreshToken = async (userId, refreshToken) => {
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60
  );
};

const setCookies = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // Prevents client-side JS from reading the cookie || prevents XSS attacks
    sameSite: "none",
    secure: process.env.NODE_ENV === "production", //prevents CSRF attacks, cross-site request forgery
    maxAge: 15 * 60 * 1000, // 15 minutes
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    sameSite: "none",
    secure: process.env.NODE_ENV === "production", //prevents CSRF attacks, cross-site request forgery
    maxAge: 7 * 24 * 60 * 1000, // 7 days
  });
};

export const signup = async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = await User.create({ name, email, password });

    // Authenticate user and generate token
    const { accessToken, refreshToken } = generateTokens(user._id);

    // Store refresh token in Redis
    await storeRefreshToken(user._id, refreshToken);
    setCookies(res, accessToken, refreshToken);

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User Created succesfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
export const getUsers = async (req, res) => {
  try {
    const allUsers = await User.find({});

    if (!allUsers) {
      return res.status(400).json({ message: "No User" });
    }

    res.status(201).json({
      allUsers,
      message: "User Created succesfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
export const getUserById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return res.status(400).json({ message: "User does not exist" });
    }

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "Operation succesfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await user.comparePassword(password))) {
      const { accessToken, refreshToken } = generateTokens(user._id);
      await storeRefreshToken(user._id, refreshToken);
      setCookies(res, accessToken, refreshToken);
      res.status(200).json({
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          accessToken,
          refreshToken,
        },
        message: "Login successful",
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    console.log("error in login controller", error);
    res.status(500).json({ message: error.message });
  }
};
export const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.accessToken;
    if (refreshToken) {
      const decoded = jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET
      );
      await redis.del(`refresh_token:${decoded.userId}`);
    }
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const refreshToken = async (req, res) => {
  console.log(req.headers.cookie);
  try {
    const refreshToken = req.headers.cookie;
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const storedToken = await redis.get(`refresh_token:${decoded.userId}`);

    if (refreshToken !== storedToken) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const accessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      maxAge: 15 * 60 * 1000,
    });

    res.status(200).json({ message: "Access token refreshed" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
};

export const editUser = async (req, res) => {
  const { password, name, role, email } = req.body;
  try {
    const userExists = await User.findById(req.params.id);

    if (email) {
      return res.status(400).json({ message: "Email cannot be changed" });
    }
    if (!userExists) {
      return res.status(400).json({ message: "User does not exists" });
    }
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { name, password, role },
      { new: true }
    );

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User Created succesfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
