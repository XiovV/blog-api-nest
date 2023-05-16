import { Inject, Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { Logger } from 'winston'

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  private readonly logger: Logger
  constructor(@Inject(WINSTON_MODULE_PROVIDER) private readonly winston: Logger) {
    this.logger = this.winston.child({ context: LoggerMiddleware.name })
  }
  use(req: Request, res: Response, next: () => void) {
    this.logger.info('incoming request', { req: { method: req.method, url: req.baseUrl, query: req.query, params: req.params, headers: req.headers } })

    res.on('finish', () => {
      this.logger.info('request completed', { res: { statusCode: res.statusCode } })
    })

    next();
  }
}
