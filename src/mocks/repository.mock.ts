import { getRepositoryToken } from "@nestjs/typeorm";
import { Post } from "src/posts/entities/post.entity";
import { PasswordResetToken } from "src/users/entities/password-reset-token.entity";
import { BlacklistedToken } from "src/users/entities/token-blacklist.entity";
import { User } from "src/users/entities/user.entity";

export const MockPostsRepository = {
    provide: getRepositoryToken(Post),
    useValue: {
        save: jest.fn().mockResolvedValue({})
    }
}

export const MockUsersRepository = {
    provide: getRepositoryToken(User),
    useValue: {
        save: jest.fn().mockResolvedValue({})
    }
}

export const MockBlacklistedTokenRepository = {
    provide: getRepositoryToken(BlacklistedToken),
    useValue: {
        save: jest.fn().mockResolvedValue({})
    }
}

export const MockPasswordResetTokenRepository = {
    provide: getRepositoryToken(PasswordResetToken),
    useValue: {
        save: jest.fn().mockResolvedValue({})
    }
}