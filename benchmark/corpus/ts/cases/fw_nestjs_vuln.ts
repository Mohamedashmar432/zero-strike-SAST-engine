import { Controller, Get, Query } from '@nestjs/common';
import { exec } from 'child_process';

@Controller('ping')
export class PingController {
  @Get()
  ping(@Query('host') host: string) {
    exec('ping -c 1 ' + host, function (err, stdout) {});
    return 'ok';
  }
}
