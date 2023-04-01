import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from "typeorm";
import { BlacklistedToken } from "./token-blacklist.entity";

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

    @Column({default: 1})
    role: number;

    @Column('text', {array: true, nullable: true})
    recovery: string[];

    @Column({default: false})
    isActive: boolean;

    @OneToMany(() => BlacklistedToken, token => token.user)
    blacklistedTokens: BlacklistedToken[]
}
