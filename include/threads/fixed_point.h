#define P 17
#define Q 14
#define F 1<<(Q)



int INT_TO_FP(int x);

int FP_TO_INT_ROUND(int x);
int FP_TO_INT(int x);

int ADD_FP(int x,int y);

int ADD_FI(int x,int i);

int SUB_FP(int x,int y);

int SUB_FI(int x,int i);

int MULT_FP(int x,int y);

int MULT_FI(int x,int i);

int DIV_FP(int x,int y);

int DIV_FI(int x,int i);

int INT_TO_FP (int x)
{
    return x * F;
}

int FP_TO_INT_ROUND (int x)
{
    if(x>=0) return (x+F/2)/F;
    else return (x-F/2)/F;
}

int FP_TO_INT (int x)
{
  return x / F;
}

int ADD_FP (int x, int y)
{
  return x + y;
}

int ADD_FI (int x, int i)
{
  return ADD_FP (x, INT_TO_FP (i));
}

int SUB_FP (int x, int y)
{
    return x-y;
}

int SUB_FI (int x, int i)
{
    return SUB_FP(x,INT_TO_FP(i));
}

int MULT_FP (int x, int y)
{
  return (int) ((int64_t) x * y / F);
}

int MULT_FI (int x, int i)
{
  return MULT_FP(x, INT_TO_FP (i));
}

int DIV_FP (int x, int i)
{
  return (int64_t) x * F / i;
}

int DIV_FI (int x, int i)
{
  return DIV_FP (x, INT_TO_FP (i));
}
