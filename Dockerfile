FROM php:8.3-cli-alpine

RUN apk add --no-cache git unzip bash icu-dev icu-data-full libsodium-dev \
    && docker-php-ext-install intl sodium

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json composer.lock* ./
RUN composer install --prefer-dist --no-interaction --optimize-autoloader

COPY . .

CMD ["vendor/bin/phpunit"]
