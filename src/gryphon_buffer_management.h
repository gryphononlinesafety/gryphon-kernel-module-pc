/*
 * Copyright (C) 2025 GryphonConnect [ https://gryphonconnect.com/ ]
 * Author: Naveen Kumar Gutti <naveen@gryphonconnect.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __GRYPHON_BUFFER_MANAGEMENT__
#define __GRYPHON_BUFFER_MANAGEMENT__
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/timer.h>

#define GRY_RAB_NUMBER_OF_ELEMENTS 200
#define RAB_TIMER_INTERVAL 4

enum {
	GRY_FRAG_CMD_UNSPEC,
	GRY_FRAG_CMD_SET,
	GRY_FRAG_CMD_GET,
	GRY_FRAG_CMD_PRINT,
	GRY_FRAG_CMD_CLEAR,
	GRY_FRAG_CMD_DEL,
	GRY_FRAG_CMD_MAX
};

struct gry_fragment_tuple_t {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
};

struct gry_fragment_tuple_payload_t {
	int cmd;
	struct gry_fragment_tuple_t tuple;
};

struct gry_frag_hash_tuple_t {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t protocol;
	unsigned long timestamp;
	struct hlist_node hnode;
};

// Insert a fragment_tuple information into the buffer
int gry_rab_set_tuple_element(struct gry_fragment_tuple_t *elem);

// Peek if a fragment_tuple information present in the buffer
int gry_rab_peek_tuple_element(struct gry_fragment_tuple_t *elem);

// Retrieve a fragment_tuple information from the buffer
int gry_rab_get_tuple_element(struct gry_fragment_tuple_t *elem);

// Delete a fragment tuple information from the buffer
int gry_rab_del_tuple_element(struct gry_fragment_tuple_t *elem);

// Print the buffer information
int gry_rab_print_tuple_elements(void);

// Clear the buffer
int gry_rab_clear_tuple_elements(void);

// function execute the RAB timer
void gry_rab_cleanup_timer_exec(struct timer_list *t);

// function to invoke the timer of RAB
void gry_rab_timer_invoke(void);

// function to destory the timer of RAB
void gry_rab_timer_destroy(void);

// function to allocate safe memory
void* gry_safe_alloc(size_t size);

// function to return memory allocation type
int gry_get_memory_alloc_type(void);
#endif
