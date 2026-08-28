// ZS-TS-089: path.join path traversal
import * as path from 'path';
const userInput: string = req.query.file as string;
const target = path.join('/var/www/uploads', userInput);
