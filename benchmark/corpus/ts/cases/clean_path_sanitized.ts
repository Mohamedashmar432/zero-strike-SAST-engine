// True negative for the path rules: path.basename and a generated random name
// cannot traverse directories (taint is cleared for file-path sinks only).
import fs from "fs";
import path from "path";
import { randomUUID } from "crypto";

const DIR = "/srv/forms";

export function loadForm(formName: string): Buffer {
  const safeName = path.basename(formName);
  const filePath = path.join(DIR, safeName);
  return fs.readFileSync(filePath);
}

export async function saveUpload(data: Buffer): Promise<string> {
  const storedName = `${randomUUID()}.pdf`;
  await fs.promises.writeFile(path.join(DIR, storedName), data);
  return storedName;
}
