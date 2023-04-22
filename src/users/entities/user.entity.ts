import { Column, Entity, JoinColumn, ManyToOne, OneToMany, OneToOne, PrimaryGeneratedColumn } from "typeorm";
import { BlacklistedToken } from "./token-blacklist.entity";
import { PasswordResetToken } from "./password-reset-token.entity";
import { Post } from "src/posts/entities/post.entity";
import { Role } from "./role.entity";

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({unique: true})
    username: string;

    @Column({unique: true})
    email: string;

    @Column()
    password: string;

    @Column({nullable: true, type: 'bytea'})
    mfaSecret: Buffer;

    @Column('text', {array: true, nullable: true})
    recovery: string[];

    @Column({default: false})
    isActive: boolean;

    @OneToMany(() => BlacklistedToken, token => token.user)
    blacklistedTokens: BlacklistedToken[]

    @OneToMany(() => PasswordResetToken, token => token.user)
    passwordResetTokens: PasswordResetToken[]

    @OneToMany(() => Post, post => post.user)
    posts: Post[]

    @ManyToOne(() => Role, role => role.users)
    role: Role
}
