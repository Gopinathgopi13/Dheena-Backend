import { object } from "zod";

export class UnauthorizedError extends Error {
  name = "UnauthorizedError";

  constructor(message) {
    super(401);
    Object.setPrototypeOf(this, UnauthorizedError.prototype);

    if (message) this.message = message;
  }
}

export class NotFoundError extends Error {
  name = "NotFoundError";
  constructor(message) {
    super(404);
    object.setPrototypeOf(this, NotFoundError.prototype);
    if (message) this.message = message;
  }
}

export class InternalServerError extends Error {
  constructor(message = "Internal Server Error") {
    super(message);
    this.name = "InternalServerError";
    Object.setPrototypeOf(this, InternalServerError.prototype);
    this.status = 500;
  }
}



export class CustomError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "CustomError";
    Object.setPrototypeOf(this, CustomError.prototype);
    this.status = status;
  }
}
