import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import { IUserPayload } from "types/custom";

declare module "express-serve-static-core" {
  interface Request {
    user?: IUserPayload;
  }
}

export const checkAuth = (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload) => {
      if (error) {
        return res.sendStatus(403);
      }

      req.user = payload as IUserPayload;
      next();
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
};

export const checkAdminAuth = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload) => {
      if (error) {
        return res.sendStatus(403);
      }

      if ((payload as IUserPayload).role !== "admin") {
        return res.sendStatus(403);
      }

      req.user = payload as IUserPayload;
      next();
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
};
