import { Controller, Get, Post, Body, Patch, Param, Delete, Version, UseGuards, ValidationPipe, Request, HttpVersionNotSupportedException } from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { JwtGuard } from 'src/auth/jwt.guard';
import { User } from 'src/users/entities/user.entity';

@Controller('posts')
export class PostsController {
  constructor(private readonly postsService: PostsService) {}

  @Version('1')
  @UseGuards(JwtGuard)
  @Post()
  create(@Body(new ValidationPipe()) createPostDto: CreatePostDto, @Request() req) {
    const user: User = req.user;

    return this.postsService.create(user, createPostDto);
  }

  @Get()
  findAll() {
    return this.postsService.findAll();
  }

  @Version('1')
  @UseGuards(JwtGuard)
  @Get(':id')
  async findOne(@Param('id') id: number) {
    return await this.postsService.findOne(id);
  }

  @Version('1')
  @UseGuards(JwtGuard)
  @Get('user/:username')
  async getUsersPosts(@Param('username') username: string) {
    return await this.postsService.getUsersPosts(username)
  }

  @Version('1')
  @UseGuards(JwtGuard)
  @Patch(':id')
  async update(@Param('id') id: number, @Body() updatePostDto: UpdatePostDto, @Request() req) {
    const user: User = req.user;
    return await this.postsService.update(user, id, updatePostDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.postsService.remove(+id);
  }
}
