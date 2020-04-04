#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#define P 17
#define Q 14
#define F (1<<(Q))

#if P+Q != 31
#error "The sum of P, Q is 31"
#endif


#define INT_TO_FP(x) ((x)*F)

#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F))
#define FP_TO_INT(x) (x)/F

#define ADD_FP(x,y) ((x)+(y))

#define ADD_FI(x,i) ((x)+(i)*F)

#define SUB_FP(x,y) ((x)-(y))

#define SUB_FI(x,i) ((x)-(i)*F)

#define MULT_FP(x,y) ((((int64_t)x)*(y))/F)

#define MULT_FI(x,i) ((x)*(i))

#define DIV_FP(x,y) (((int64_t)x)*(F))/(y)

#define DIV_FI(x,i) ((x)/(i))

#endif
