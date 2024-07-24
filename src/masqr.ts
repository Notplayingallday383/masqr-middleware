import path from "path";
import fs from "fs";
import type { Request, Response, NextFunction } from "express";

type MasqrConfig = {
  licenseServer: string;
  whitelist: string[];
}

export async function masqrCheck(config: MasqrConfig, htmlFile: string): Promise<Function> {
  let loadedHTMLFile = fs.readFileSync(htmlFile, "utf8");
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.headers.host && config.whitelist.includes(req.headers.host)) {
      next();
      return;
    }
    const authheader = req.headers.authorization;
    if (req.cookies["authcheck"]) {
      next();
      return;
    }
    if (!authheader) {
      res.setHeader("WWW-Authenticate", "Basic");
      res.status(401);
      MasqFail(req, res, loadedHTMLFile);
      return;
    }
    // If we are at this point, then the request should be a valid masqr request, and we are going to check the license server
    const auth = Buffer.from(authheader.split(" ")[1], "base64").toString().split(":");
    const pass = auth[1];

    const licenseCheck = (await (await fetch(config.licenseServer + pass + "&host=" + req.headers.host)).json())["status"];

    if (licenseCheck === "License valid") {
      // Authenticated, set cookie for a year
      res.cookie("authcheck", "true", {
        expires: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      });
      res.send(`<script>window.location.href = window.location.href</script>`); // fun hack to make the browser refresh and remove the auth params from the URL
      return;
    }
  }
}

async function MasqFail(req: Request, res: Response, failureFile: string) {
  if (!req.headers.host) {
    return;
  }
  const unsafeSuffix = req.headers.host + ".html";
  let safeSuffix = path.normalize(unsafeSuffix).replace(/^(\.\.(\/|\\|$))+/, "");
  let safeJoin = path.join(process.cwd() + "/Masqrd", safeSuffix);
  try {
    await fs.promises.access(safeJoin); // man do I wish this was an if-then instead of a "exception on fail"
    const failureFileLocal = await fs.promises.readFile(safeJoin, "utf8");
    res.setHeader("Content-Type", "text/html");
    res.send(failureFileLocal);
    return;
  } catch (e) {
    res.setHeader("Content-Type", "text/html");
    res.send(failureFile);
    return;
  }
}
