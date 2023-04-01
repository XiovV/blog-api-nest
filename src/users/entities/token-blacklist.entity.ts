import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { User } from "./user.entity";

@Entity()
export class BlacklistedToken {
    @PrimaryGeneratedColumn()
    id: number

    @Column({unique: true})
    token: string

    @ManyToOne(() => User, user => user.blacklistedTokens)
    user: User
}