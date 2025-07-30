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

#include <linux/version.h>
#include "gryphon_buffer_management.h"

static DEFINE_SPINLOCK(gry_rab_lock);
static DEFINE_HASHTABLE(fragment_table, 8);
static struct timer_list rab_cleanup_timer;

static inline u32 gry_fragment_tuple_calculate_hash(const struct gry_fragment_tuple_t *key){
	return jhash(key, sizeof(struct gry_fragment_tuple_t), 0);
}

int gry_rab_set_tuple_element(struct gry_fragment_tuple_t *elem) {
	u32 hash;
	struct gry_frag_hash_tuple_t *entry;

	hash = gry_fragment_tuple_calculate_hash(elem);
	entry = (struct gry_frag_hash_tuple_t*)gry_safe_alloc(sizeof(struct gry_frag_hash_tuple_t));
	if(!entry){
		printk(KERN_ERR "GRY_FRAG_HASH_TUPLE_T:NO_MEM\n");
		return -1;
	}
	entry->saddr = elem->saddr;
	entry->daddr = elem->daddr;
	entry->sport = elem->sport;
	entry->dport = elem->dport;
	entry->protocol = elem->protocol;
	entry->timestamp = jiffies;
	spin_lock_bh(&gry_rab_lock);
	hash_add(fragment_table, &entry->hnode, hash);
	spin_unlock_bh(&gry_rab_lock);
	return 0;
}

int gry_rab_peek_tuple_element(struct gry_fragment_tuple_t *elem){
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		if(entry->saddr == elem->saddr && entry->daddr == elem->daddr && entry->sport == elem->sport && entry->dport == elem->dport && entry->protocol == elem->protocol){
			spin_unlock_bh(&gry_rab_lock);
			return 0;
		}
	}
	spin_unlock_bh(&gry_rab_lock);
	return -1;
}

int gry_rab_get_tuple_element(struct gry_fragment_tuple_t *elem) {
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		if(entry->saddr == elem->saddr && entry->daddr == elem->daddr && entry->sport == elem->sport && entry->dport == elem->dport && entry->protocol == elem->protocol){
			hash_del(&entry->hnode);
			kfree(entry);
			spin_unlock_bh(&gry_rab_lock);
			return 0;
		}
	}
	spin_unlock_bh(&gry_rab_lock);
	return -1;
}

int gry_rab_print_tuple_elements() {
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		printk(KERN_INFO "GRY_RAB_TUPLE: %u %u %u %u %u\n", entry->saddr, entry->daddr, entry->sport, entry->dport, entry->protocol);
	}
	spin_unlock_bh(&gry_rab_lock);
	return 0;
}

int gry_rab_clear_tuple_elements() {
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		hash_del(&entry->hnode);
		kfree(entry);
	}
	spin_unlock_bh(&gry_rab_lock);
	return 0;
}

int gry_rab_del_tuple_element(struct gry_fragment_tuple_t *elem) {
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		if(entry->saddr == elem->saddr && entry->daddr == elem->daddr && entry->sport == elem->sport && entry->dport == elem->dport && entry->protocol == elem->protocol){
			hash_del(&entry->hnode);
			kfree(entry);
			spin_unlock_bh(&gry_rab_lock);
			return 0;
		}
	}
	spin_unlock_bh(&gry_rab_lock);
	return -1;
}

void gry_rab_cleanup_timer_exec(struct timer_list *t){
	u32 bkt;
	struct gry_frag_hash_tuple_t *entry;
	int count = 0, del_count = 0;
	spin_lock_bh(&gry_rab_lock);
	hash_for_each(fragment_table, bkt, entry, hnode){
		if(jiffies - entry->timestamp > msecs_to_jiffies(RAB_TIMER_INTERVAL * 1000)){
			hash_del(&entry->hnode);
			kfree(entry);
			del_count++;
		}
		count++;
	}
	spin_unlock_bh(&gry_rab_lock);
	// printk(KERN_INFO "GRY_RAB_TIMER_TRIGGER: [%d] [%d]\n", count, del_count);
	// trigger the timer again
	mod_timer(&rab_cleanup_timer, jiffies + msecs_to_jiffies(RAB_TIMER_INTERVAL * 1000));
}

void gry_rab_timer_invoke(void){
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	// setup the timer
	timer_setup(&rab_cleanup_timer, gry_rab_cleanup_timer_exec, 0);

	// trigger the timer
	mod_timer(&rab_cleanup_timer, jiffies + msecs_to_jiffies(RAB_TIMER_INTERVAL * 1000));
#else
	init_timer(&rab_cleanup_timer);
	rab_cleanup_timer.function = gry_rab_cleanup_timer_exec;
	rab_cleanup_timer.data = NULL;
	rab_cleanup_timer.expires = jiffies + msecs_to_jiffies(RAB_TIMER_INTERVAL * 1000);

	add_timer(&rab_cleanup_timer);
#endif
}

void gry_rab_timer_destroy(void){
	del_timer_sync(&rab_cleanup_timer);
}

void* gry_safe_alloc(size_t size){
	if(in_atomic()){
		return kmalloc(size, GFP_ATOMIC);
	}
	return kmalloc(size, GFP_KERNEL);
}

int gry_get_memory_alloc_type(){
	if(in_atomic())
		return GFP_ATOMIC;
	return GFP_KERNEL;
}
