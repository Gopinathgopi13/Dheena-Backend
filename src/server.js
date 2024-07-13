import express from "express";
import authRouter from "./routes/authRoute";

let app = express();

app.use("/api/auth", authRouter);

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
