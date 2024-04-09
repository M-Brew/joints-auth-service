import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import User from "../models/user.model";
import RefreshToken from "../models/refreshToken.model";

import { signInValidation, signUpValidation } from "../validation/authValidation";
import { generateAccessToken, generateRefreshToken } from "../utils/generateToken";
import { IUserPayload } from "types/custom";
import { checkAuth } from "../middlewares/checkAuth";

const router = Router();

router.post("/sign-up", async (req: Request, res: Response) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    const { valid, errors } = signUpValidation({
      firstName,
      lastName,
      email,
      password,
    });
    if (!valid) {
      return res.status(400).json({ errors });
    }

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ error: "User with email exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });
    await newUser.save();

    const payload: IUserPayload = {
      id: newUser._id.toString(),
      name: `${newUser.firstName} ${newUser.lastName}`,
      email: newUser.email,
      role: newUser.role,
    };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await new RefreshToken({ token: refreshToken }).save();

    return res.status(201).json({
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

router.post("/sign-in", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const { valid, errors } = signInValidation({ email, password });
    if (!valid) {
      return res.status(400).json({ errors });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const payload: IUserPayload = {
      id: user._id.toString(),
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
      role: user.role,
    };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await new RefreshToken({ token: refreshToken }).save();

    return res.status(200).json({
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

router.post("/admin-sign-in", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const { valid, errors } = signInValidation({ email, password });
    if (!valid) {
      return res.status(400).json({ errors });
    }

    const user = await User.findOne({ email, role: "admin" });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const payload: IUserPayload = {
      id: user._id.toString(),
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
      role: user.role,
    };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await new RefreshToken({ token: refreshToken }).save();

    return res.status(200).json({
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

router.post("/token", async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.sendStatus(401);
    }

    const refreshToken = await RefreshToken.findOne({ token });
    if (!refreshToken) {
      return res.sendStatus(403);
    }

    const payload = jwt.verify(
      refreshToken.token,
      process.env.REFRESH_TOKEN_SECRET
    ) as IUserPayload;
    const accessToken = generateAccessToken({
      id: payload.id,
      name: payload.name,
      email: payload.email,
      role: payload.role,
    });

    return res.status(200).json({ accessToken });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

router.get("/data", checkAuth, async (req: Request, res: Response) => {
  try {
    const user = req.user;
    return res.status(200).json(user);
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

router.post("/sign-out", async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.sendStatus(401);
    }

    const refreshToken = await RefreshToken.findOne({ token });
    if (!refreshToken) {
      return res.sendStatus(401);
    }

    await RefreshToken.findByIdAndDelete(refreshToken._id);

    return res.sendStatus(204);
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
});

export default router;
