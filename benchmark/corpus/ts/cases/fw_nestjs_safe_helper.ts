import { Controller, Get } from '@nestjs/common';
import { exec } from 'child_process';

// The helper's parameter only ever receives a constant from the handler and
// the framework binds nothing to it: no finding.
@Controller('version')
export class VersionController {
  @Get()
  version() {
    this.launch('--version');
    return 'ok';
  }

  launch(flag: string) {
    exec('tool ' + flag, function (err, stdout) {});
  }
}
