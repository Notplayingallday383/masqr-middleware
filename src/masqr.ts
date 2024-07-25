import path from "path";
import fs from "fs";
import type { Request, Response, NextFunction } from "express";

type MasqrConfig = {
  licenseServer: string;
  whitelist: string[];
}

export async function masqrCheck(config: MasqrConfig, htmlFile: string, idFile: string): Promise<Function> {
  let loadedHTMLFile = fs.readFileSync(htmlFile, "utf8");
  let storedIDs = [];
  if (fs.existsSync(idFile)) {
    const data = fs.readFileSync(idFile, "utf8");
    storedIDs = JSON.parse(data);
  }
  // Save the data to a file incase your server kills itself or something
  setInterval(() => {
    const data = JSON.stringify(storedIDs);
    fs.writeFile(idFile, data, (res) => {console.log('Saved Data')});
  }, 5000);
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.headers.host && config.whitelist.includes(req.headers.host)) {
      next();
      return;
    }
    const authheader = req.headers.authorization;
    if (req.cookies["authcheck"]) {
      const isVerified = storedIDs.includes(req.cookies["authcheck"]);
      if (isVerified) {
        next();
        return;
      } else {
        res.setHeader("Content-Type", "text/html"); 
        return res.status(401).send(failureFile);
      }
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
      const characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
      let code = '';
      for (let i = 0; i < 5; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        code += characters[randomIndex];
      }
      storedIDs.push(code);
      res.cookie("authcheck", code, {
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
