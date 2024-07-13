import winston, { format } from "winston";
const { combine, timestamp, colorize, label, printf } = format;

const customLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    verbose: 4,
    debug: 5,
    silly: 6,
  },
  colors: {
    error: "red",
    warn: "yellow",
    info: "green",
    http: "magenta",
    verbose: "cyan",
    debug: "blue",
    silly: "rainbow",
  },
};

winston.addColors(customLevels.colors);

const myFormat = printf(({ level, message, label, timestamp }) => {
  const labelColor = `\x1b[35m${label}\x1b[0m`;
  const timestampColor = `\x1b[36m${timestamp}\x1b[0m`;
  return `${timestampColor} [${labelColor}] ${level}: ${message}`;
});

const logger = winston.createLogger({
  levels: customLevels.levels,
  format: combine(label({ label: "logger..!" }), timestamp(), myFormat),
  transports: [
    new winston.transports.Console({
      format: combine(colorize({ all: true }), myFormat),
    }),
    // new winston.transports.File({ filename: "log/error.log", level: "error" }),
    // new winston.transports.File({ filename: "log/all-log" }),
  ],
});
export default logger;
