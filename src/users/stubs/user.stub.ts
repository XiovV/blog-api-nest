import { Role } from "../entities/role.entity";
import { BlacklistedToken } from "../entities/token-blacklist.entity";
import { User } from "../entities/user.entity";

export const userStub = (): User => {
    return {
        id: 1,
        username: "user",
        email: "user@email.com",
        password: "password",
        mfaSecret: new Buffer("sdf"),
        recovery: ["recovery1", "recovery2"],
        isActive: true,
        blacklistedTokens: [],
        passwordResetTokens: [],
        posts: [],
        role: new Role()
    }
}