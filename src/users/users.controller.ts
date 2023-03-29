import { Controller, Get, Post, Body, Patch, Param, Delete, Version, ValidationPipe, Request, HttpStatus, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LocalAuthGuard } from 'src/auth/local-auth.guard';
import { AuthService } from 'src/auth/auth.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService, private authService: AuthService) { }

  @Version('1')
  @Post('register')
  async create(@Body(new ValidationPipe()) createUserDto: CreateUserDto) {
    const createdUser = await this.usersService.create(createUserDto);

    return await this.authService.generateTokenPair(createdUser);
  }

  @Version('1')
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Request() req) {
    return this.authService.login(req.user)
  }

  @Version('1')
  @Get('mfa')
  setupMfa() {
    const secret = this.authService.generateMfaSecret();

    return { secret }
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
}
