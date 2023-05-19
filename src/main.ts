import { VersioningType } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true});
  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER))
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

  await app.listen(process.env.PORT || 3000);
}
bootstrap();
