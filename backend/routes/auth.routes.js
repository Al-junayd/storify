import express from "express";
import {
  login,
  logout,
  signup,
  getUsers,
  getUserById,
  refreshToken,
  editUser,
} from "../controllers/auth.controller.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/refresh-token", refreshToken);
router.get("/users", getUsers);
router.get("/users/:id", getUserById);
router.put("/user/edit/:id", editUser);

export default router;
