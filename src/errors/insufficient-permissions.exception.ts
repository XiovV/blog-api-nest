import { HttpException, HttpStatus } from "@nestjs/common";

export class InsufficientPermissionsException extends HttpException {
    constructor() {
        super('Insufficient Permissions', HttpStatus.FORBIDDEN)
    }
}