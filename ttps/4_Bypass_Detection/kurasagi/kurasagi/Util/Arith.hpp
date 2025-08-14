/*
 * @file Arith.hpp
 * @brief Arithmetics utility.
 */

#include "../Include.hpp"

/*
 * @brief determine if [v1Start, v1End] and [v2Start, v2End] has shared area i.e. collapsing.
 * @return `TRUE` if collapsing, `FALSE` otherwise.
 */
BOOLEAN IsCollapsing(ULONG64 v1Start, ULONG64 v1End, ULONG64 v2Start, ULONG64 v2End);