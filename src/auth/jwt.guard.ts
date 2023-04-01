import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { Request } from "express";
import { UsersService } from "src/users/users.service";

@Injectable()
export class JwtGuard implements CanActivate {
    constructor(private jwtService: JwtService, private config: ConfigService, private usersService: UsersService) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        if (!token) {
            throw new UnauthorizedException();
        }

        try {
            const payload = await this.jwtService.verifyAsync(token, {secret: this.config.get('JWT_SECRET')});

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