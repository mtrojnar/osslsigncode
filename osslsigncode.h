/*
 * osslsigncode support library
 *
 * Copyright (C) 2021 Michał Trojnara <Michal.Trojnara@stunnel.org>
 * Author: Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
 *
 */

int bio_hash_data(char *indata, BIO *hash, uint32_t idx, uint32_t fileend);
