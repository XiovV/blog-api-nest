import { MinLength } from "class-validator"
import { authConstants } from "src/auth/constants"

export class LoginUserRecoveryDto {
    @MinLength(5)
    password: string

    @MinLength(2)
    username: string

    @MinLength(authConstants.recoveryCodeLength)
    recoveryCode: string 
}