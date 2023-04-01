import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService, JwtVerifyOptions } from "@nestjs/jwt";
import { Request } from "express";
import { UsersService } from "src/users/users.service";

@Injectable()
export class JwtGuard implements CanActivate {
    constructor(private jwtService: JwtService, private config: ConfigService, private usersService: UsersService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request: Request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        if (!token) {
            throw new UnauthorizedException();
        }

        const verifyTokenOptions: JwtVerifyOptions = {
            secret: this.config.get('JWT_SECRET'),
            ignoreExpiration: request.url === '/v1/users/token/refresh' ? false : true
        }

        try {
            const payload = await this.jwtService.verifyAsync(token, verifyTokenOptions);

            const user = await this.usersService.findOneById(payload.sub);
            request['user'] = user;
        } catch {
            throw new UnauthorizedException();
        }

        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        if (!request.headers.authorization) {
            return undefined;
        }

        const [type, token] = request.headers.authorization.split(' ');
        return type === 'Bearer' ? token : undefined;
    }
}