import { HttpStatus } from "@nestjs/common";
import { ApiProperty } from "@nestjs/swagger";
import { NumericLimit } from "argon2";

export class TokenPair {
    @ApiProperty()
    accessToken: string

    @ApiProperty()
    refreshToken: string
}

export class ErrorResponse {
    @ApiProperty()
    message: string
}

export class BadRequestError extends ErrorResponse {
    @ApiProperty({default: HttpStatus.BAD_REQUEST})
    statusCode: number
}

export class NotFoundError extends ErrorResponse {
    @ApiProperty({default: HttpStatus.NOT_FOUND})
    statusCode: number
}

export class DefaultNotFoundError extends NotFoundError {
    @ApiProperty({default: "Not Found"})
    message: string;
}

export class ForbiddenError extends ErrorResponse {
    @ApiProperty({default: HttpStatus.FORBIDDEN})
    statusCode: number
}

export class ConflictError extends ErrorResponse {
    @ApiProperty({default: HttpStatus.CONFLICT})
    statusCode: number
}

export class UnauthorizedError extends ErrorResponse {
    @ApiProperty({default: HttpStatus.UNAUTHORIZED})
    statusCode: number
}

export class DefaultUnauthorizedError extends UnauthorizedError {
    @ApiProperty({default: "Unauthorized"})
    message: string
}

export class InsufficientPermissionsError extends ForbiddenError {
    @ApiProperty({default: "Insufficient Permissions"})
    message: string
}

export class SetupMFAResponse {
    @ApiProperty()
    secret: string
}