import { Column, Entity, PrimaryGeneratedColumn } from "typeorm";

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

    @Column({nullable: true})
    mfaSecret: string;

    @Column({default: 1})
    role: number;

    @Column('text', {array: true, nullable: true})
    recovery: string[];

    @Column({default: false})
    isActive: boolean;
}
