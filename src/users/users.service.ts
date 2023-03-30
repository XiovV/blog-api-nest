import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import * as argon2 from 'argon2';

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private usersRepository: Repository<User>) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = new User();
    user.username = createUserDto.username;
    user.email = createUserDto.email;
    user.password = await argon2.hash(createUserDto.password);

    const existingUsername = await this.usersRepository.findOneBy({username: createUserDto.username});
    if (existingUsername) {
      throw new HttpException('username already exists', HttpStatus.BAD_REQUEST);
    }

    const existingEmail = await this.usersRepository.findOneBy({email: createUserDto.email})
    if (existingEmail) {
      throw new HttpException('email already exists', HttpStatus.BAD_REQUEST);
    }

    const result = await this.usersRepository.insert(user);

    user.id = result.identifiers[0].id;
    
    return user; 
  }

  async findOneByUsername(username: string): Promise<User | undefined> {
    return await this.usersRepository.findOneBy({username: username})
  }

  async saveMfaDetails(user: User, secret: Buffer, recoveryCodes: string[]) {
    user.recovery = recoveryCodes;
    user.mfaSecret = ("\\x" + secret.toString("hex")) as any;

    this.usersRepository.save(user);
  }

  findAll() {
    return `This action returns all users`;
  }

  async findOneById(id: number): Promise<User | undefined> {
    return await this.usersRepository.findOneBy({id: id})
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }

}
