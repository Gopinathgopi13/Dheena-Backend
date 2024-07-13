import { ZodError } from "zod";

function errorMiddleware(error, _request, response, _next) {
  const stack = error.stack;

  if (error instanceof ZodError) {
    return response.status(400).json({
      status: false,
      message: "Invalid request",
      errors: error.errors.map((err) => err.message),
      stack,
    });
  }

  return response
    .status(error?.code === "P2025" ? 404 : error.httpCode ?? 500)
    .json({
      status: false,
      message: error.message || "internal server error",
      stack,
    });
}

export default errorMiddleware;
