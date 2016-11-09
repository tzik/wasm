
namespace irt {

long syscall(long, long);
long syscall(long, long, long);
long syscall(long, long, long, long);
long syscall(long, long, long, long, long);
long syscall(long, long, long, long, long, long);
long syscall(long, long, long, long, long, long, long);
  
long syscallv(long nr, va_list argp) {
  switch (nr) {
    case 0:
    case 2:
    case 20:
    case 24:
    case 29:
    case 36:
    case 47:
    case 49:
    case 50:
    case 64:
    case 65:
    case 66:
    case 68:
    case 111:
    case 153:
    case 158:
    case 190:
    case 199:
    case 200:
    case 201:
    case 202:
    case 224:
    case 291: {
      return irt::syscall(nr);
    }
      
    case 1:
    case 6:
    case 10:
    case 12:
    case 13:
    case 22:
    case 23:
    case 25:
    case 27:
    case 34:
    case 40:
    case 41:
    case 42:
    case 43:
    case 45:
    case 46:
    case 51:
    case 59:
    case 60:
    case 61:
    case 69:
    case 72:
    case 73:
    case 82:
    case 86:
    case 90:
    case 109:
    case 110:
    case 113:
    case 115:
    case 116:
    case 118:
    case 122:
    case 124:
    case 132:
    case 133:
    case 136:
    case 138:
    case 139:
    case 147:
    case 148:
    case 149:
    case 152:
    case 157:
    case 159:
    case 160:
    case 213:
    case 214:
    case 215:
    case 216:
    case 243:
    case 244:
    case 246:
    case 252:
    case 254:
    case 258:
    case 262:
    case 263:
    case 278:
    case 310:
    case 323:
    case 329:
    case 332:
    case 344:
    case 374: {
      long arg1 = va_arg(argp, long);
      return irt::syscall(nr, arg1);
    }
      
    case 8:
    case 9:
    case 15:
    case 18:
    case 28:
    case 30:
    case 33:
    case 37:
    case 38:
    case 39:
    case 48:
    case 52:
    case 57:
    case 62:
    case 63:
    case 70:
    case 71:
    case 74:
    case 75:
    case 76:
    case 77:
    case 78:
    case 79:
    case 80:
    case 81:
    case 83:
    case 84:
    case 87:
    case 91:
    case 92:
    case 93:
    case 94:
    case 96:
    case 99:
    case 100:
    case 102:
    case 105:
    case 106:
    case 107:
    case 108:
    case 121:
    case 129:
    case 134:
    case 143:
    case 150:
    case 151:
    case 154:
    case 155:
    case 161:
    case 162:
    case 166:
    case 176:
    case 179:
    case 183:
    case 184:
    case 185:
    case 186:
    case 191:
    case 193:
    case 194:
    case 195:
    case 196:
    case 197:
    case 203:
    case 204:
    case 205:
    case 206:
    case 217:
    case 235:
    case 236:
    case 237:
    case 238:
    case 245:
    case 261:
    case 264:
    case 265:
    case 266:
    case 271:
    case 281:
    case 290:
    case 293:
    case 311:
    case 322:
    case 326:
    case 328:
    case 331:
    case 338:
    case 343:
    case 346:
    case 356:
    case 363:
    case 373:
    case 375: {
      long arg1 = va_arg(argp, long);
      long arg2 = va_arg(argp, long);
      return irt::syscall(nr, arg1, arg2);
    }      

    case 3:
    case 4:
    case 5:
    case 7:
    case 11:
    case 14:
    case 16:
    case 19:
    case 54:
    case 55:
    case 67:
    case 72:
    case 85:
    case 89:
    case 95:
    case 97:
    case 103:
    case 104:
    case 125:
    case 126:
    case 128:
    case 135:
    case 141:
    case 144:
    case 145:
    case 146:
    case 156:
    case 164:
    case 165:
    case 168:
    case 170:
    case 171:
    case 178:
    case 182:
    case 198:
    case 207:
    case 208:
    case 209:
    case 210:
    case 211:
    case 212:
    case 218:
    case 219:
    case 220:
    case 221:
    case 225:
    case 232:
    case 233:
    case 234:
    case 241:
    case 242:
    case 248:
    case 249:
    case 253:
    case 259:
    case 268:
    case 269:
    case 270:
    case 276:
    case 282:
    case 289:
    case 292:
    case 296:
    case 299:
    case 301:
    case 304:
    case 306:
    case 307:
    case 312:
    case 318:
    case 321:
    case 330:
    case 342:
    case 350:
    case 351:
    case 354:
    case 355:
    case 357:
    case 359:
    case 361:
    case 362:
    case 367:
    case 368:
    case 370:
    case 372:
    case 376: {
      long arg1 = va_arg(argp, long);
      long arg2 = va_arg(argp, long);
      long arg3 = va_arg(argp, long);
      return irt::syscall(nr, arg1, arg2, arg3);
    }
      
    case 26:
    case 88:
    case 114:
    case 131:
    case 174:
    case 175:
    case 177:
    case 180:
    case 181:
    case 187:
    case 229:
    case 230:
    case 231:
    case 239:
    case 250:
    case 255:
    case 256:
    case 260:
    case 267:
    case 272:
    case 277:
    case 283:
    case 287:
    case 294:
    case 295:
    case 297:
    case 300:
    case 302:
    case 305:
    case 314:
    case 315:
    case 316:
    case 320:
    case 324:
    case 325:
    case 327:
    case 335:
    case 340:
    case 345:
    case 352:
    case 360:
    case 364: {
      long arg1 = va_arg(argp, long);
      long arg2 = va_arg(argp, long);
      long arg3 = va_arg(argp, long);
      long arg4 = va_arg(argp, long);
      return irt::syscall(nr, arg1, arg2, arg3, arg4);
    }
      
    case 21:
    case 120:
    case 140:
    case 142:
    case 163:
    case 172:
    case 226:
    case 227:
    case 228:
    case 247:
    case 257:
    case 275:
    case 279:
    case 280:
    case 284:
    case 286:
    case 288:
    case 298:
    case 303:
    case 309:
    case 333:
    case 334:
    case 336:
    case 337:
    case 339:
    case 341:
    case 349:
    case 353:
    case 358:
    case 365:
    case 366: {
      long arg1 = va_arg(argp, long);
      long arg2 = va_arg(argp, long);
      long arg3 = va_arg(argp, long);
      long arg4 = va_arg(argp, long);
      long arg5 = va_arg(argp, long);
      return irt::syscall(nr, arg1, arg2, arg3, arg4, arg5);
    }
      
    case 117:
    case 120:
    case 192:
    case 240:
    case 274:
    case 308:
    case 313:
    case 317:
    case 319:
    case 347:
    case 348:
    case 369:
    case 371: {
      long arg1 = va_arg(argp, long);
      long arg2 = va_arg(argp, long);
      long arg3 = va_arg(argp, long);
      long arg4 = va_arg(argp, long);
      long arg5 = va_arg(argp, long);
      long arg6 = va_arg(argp, long);
      return irt::syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
    }
    default:
      return -ENOSYS;
  }
}

}  // namespace irt

extern "C" long __syscall(long nr, ...) {
  va_list argp;
  va_start(argp, nr);
  long ret = irt::syscall_v(nr, argp);
  va_end(argp);
  return ret;
}

extern "C" long __syscall0(long nr) {
  return irt::syscall(nr);
}

extern "C" long __syscall1(long nr, long arg1) {
  return irt::syscall(nr, arg1);
}

extern "C" long __syscall2(long nr, long arg1, long arg2) {
  return irt::syscall(nr, arg1, arg2);
}

extern "C" long __syscall3(long nr, long arg1, long arg2, long arg3) {
  return irt::syscall(nr, arg1, arg2, arg3);
}

extern "C" long __syscall4(long nr, long arg1, long arg2, long arg3,
                           long arg4) {
  return irt::syscall(nr, arg1, arg2, arg3, arg4);
}

extern "C" long __syscall5(long nr, long arg1, long arg2, long arg3, long arg4,
                          long arg5) {
  return irt::syscall(nr, arg1, arg2, arg3, arg4, arg5);
}

extern "C" long __syscall6(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6) {
  return irt::syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6);
}

extern "C" long __syscall7(long nr, long arg1, long arg2, long arg3, long arg4,
                           long arg5, long arg6, long arg7) {
  return irt::syscall(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}
