import express from "express";
import authRouter from "./routes/authRoute.js";
import config from "./config/config.js";
import logger from "./loaders/logger.js";
import cookieSession from "cookie-session";
import cors from "cors";
let app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cookieSession({ name: "session", keys: ["lama"], maxAge: 24 * 60 * 60 * 100 })
);

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: "GET, POST, PUT, DELETE",
    credentials: true,
  })
);

app.get("/", (req, res) => {
  res.send("site is working");
});

app.use("/api/auth", authRouter);

app.listen(config.port, () =>
  logger.info(`Server running in port: ${config.port}`)
);
