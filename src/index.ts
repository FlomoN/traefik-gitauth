import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import fetch from "node-fetch";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();

const config = {
  CLIENT_ID: process.env.GITHUB_CLIENT_ID,
  CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
  GITHUB_SCOPE: process.env.GITHUB_SCOPE,
  DEFAULT_ORG: process.env.GITHUB_DEFAULT_ORG,
  OAUTH_JWT_REFRESH_SECRET: process.env.OAUTH_JWT_REFRESH_SECRET,
  FQDN: process.env.FQDN,
  SCOPE: process.env.SCOPE,
};

app.use(cors({ credentials: true }));
app.use(bodyParser.json());
app.use(cookieParser());

/**
 * Allow calls from web components with cookies
 */
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  next();
});

app.get("/", async (req, res) => {
  res.send(config);
});

app.get("/auth", async (req, res) => {
  // Decode jwt
  try {
    const { refresh_token } = req.cookies;
    const result: any = jwt.verify(
      refresh_token,
      config.OAUTH_JWT_REFRESH_SECRET!
    );
    console.log(result);
    if (!(result.orgs as string[]).includes(config.DEFAULT_ORG!))
      throw new Error("User is not authenticated");
    res.status(200);
    res.send("OK");
  } catch (error) {
    console.log(req.headers);
    const redirect =
      typeof req.headers["x-forwarded-host"] !== "undefined"
        ? `redirect=${req.headers["x-forwarded-proto"]}://${req.headers["x-forwarded-host"]}`
        : ``;
    res.redirect(`/login/?${redirect}`);
  }
});

app.get("/logout", (req, res) => {
  // When deleting a cookie you need to also include the path and domain
  res.clearCookie("refresh_token", { domain: config.SCOPE });
  res.redirect("/");
});

app.get("/login", (req, res) => {
  // get a redirect query parameter
  const redirect =
    // if we have a redirect query then use it
    typeof req.query.redirect !== "undefined"
      ? `redirect=${req.query.redirect}`
      : // else if there is an x-forwared-host defined then use that
      typeof req.headers["x-forwarded-host"] !== "undefined"
      ? `redirect=${req.headers["x-forwarded-proto"]}://${req.headers["x-forwarded-host"]}`
      : // else just redirect to the home page.
        `redirect=${config.FQDN}/auth`;

  res.redirect(
    `https://github.com/login/oauth/authorize?client_id=${config.CLIENT_ID}&scope=${config.GITHUB_SCOPE}&redirect_uri=${config.FQDN}/login/callback?${redirect}`
  );
});

app.get("/login/callback", async (req, res, next) => {
  const { code } = req.query;

  try {
    // get the access token
    const { access_token } = await (
      await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: config.CLIENT_ID,
          client_secret: config.CLIENT_SECRET,
          code,
        }),
      })
    ).json();

    console.log(access_token);

    // get the username from github
    const userFetch = await (
      await fetch("https://api.github.com/graphql", {
        method: "POST",
        headers: {
          Authorization: `bearer ${access_token}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body:
          ' \
    { \
      "query": "query { viewer { login email organizations(first:100){ nodes { login }}}}" \
    } \
  ',
      })
    ).json();

    const userName = userFetch.data.viewer.login;
    const orgs = userFetch.data.viewer.organizations.nodes.map(
      (elem: any) => elem.login
    );

    // Create JWT for the user
    const refreshJwtToken = await jwt.sign(
      { name: userName, orgs },
      config.OAUTH_JWT_REFRESH_SECRET!,
      {
        expiresIn: "7d",
      }
    );

    if (!(orgs as string[]).includes(config.DEFAULT_ORG!)) {
      res.status(403);
      res.send("Not authorized");
    } else {
      res.cookie("refresh_token", refreshJwtToken, {
        httpOnly: true,
        domain: config.SCOPE,
      });

      console.log("Finally Redirecting to", req.query.redirect);

      res.redirect(req.query.redirect as string);
    }
    // if the user specified a redirect url then redirect with a cookie
  } catch (error) {
    next(error);
  }
});

app.listen(3000, () => {
  console.log("Listening on 3000.");
});
