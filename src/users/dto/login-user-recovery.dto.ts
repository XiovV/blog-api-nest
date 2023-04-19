import { ApiOperation, ApiParam, ApiProperty } from "@nestjs/swagger"
import { MinLength } from "class-validator"
import { authConstants } from "src/auth/constants"

export class LoginUserRecoveryDto {
    @ApiProperty({
        minimum: 5
    })
    @MinLength(5)
    password: string

    @ApiProperty({
        minimum: 2
    })
    @MinLength(2)
    username: string

    @ApiProperty({
        minimum: authConstants.recoveryCodeLength
    })
    @MinLength(authConstants.recoveryCodeLength)
    recoveryCode: string 
}