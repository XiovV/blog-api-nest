import { Controller, Get, Post, Body, Patch, Param, Delete, Version, UseGuards, ValidationPipe, Request, HttpVersionNotSupportedException, UnauthorizedException } from '@nestjs/common';
import { PostsService } from './posts.service';
import { CreatePostDto } from './dto/create-post.dto';
import { UpdatePostDto } from './dto/update-post.dto';
import { JwtGuard } from 'src/auth/jwt.guard';
import { User } from 'src/users/entities/user.entity';
import { Post as PostEntity } from './entities/post.entity';

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

  @Version('1')
  @UseGuards(JwtGuard)
  @Delete(':id')
  async remove(@Param('id') id: number, @Request() req) {
    const user: User = req.user;

    const post: PostEntity = await this.postsService.findOne(id);
    if (post.user.id !== user.id) {
      throw new UnauthorizedException();
    }    

    return await this.postsService.remove(user, id);
  }
}
