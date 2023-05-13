import { VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { Logger } from 'nestjs-pino';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true});
  app.useLogger(app.get(Logger))
  app.enableVersioning({
    type: VersioningType.URI,
  });

  const config = new DocumentBuilder()
  .setTitle('NestJS Blog API V1')
  .setDescription('Blog API is a simple real-world RESTful API, built in NestJS. It allows you to create users and posts, as well as manage them.')
  .setVersion('1.0')
  .addBearerAuth()
  .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(3000);
}
bootstrap();
