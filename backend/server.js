import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
import { connectDB } from "./lib/db.js";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json()); // for parsing application/json

app.use("/api/auth", authRoutes);
app.use(cookieParser());

app.listen(PORT, () => {
  console.log("Server is running on http://localhost:" + PORT);

  connectDB();
});
