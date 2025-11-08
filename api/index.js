import serverless from "serverless-http";
import app from "../src/app.js";

const handler = serverless(app, {
  onError: (err, event, context) => {
    console.error("[vercel] handler error", err);
    throw err;
  },
});

export default async function vercelHandler(req, res) {
  return handler(req, res);
}

export const config = {
  api: {
    bodyParser: false,
    externalResolver: true,
  },
};
