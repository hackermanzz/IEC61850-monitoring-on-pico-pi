#include "analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc,char**argv){
    FILE*f=fopen(argv[1],"rb"); int drop_every = argc>2?atoi(argv[2]):0;
    static uint8_t buf[2000]; uint64_t ts; uint32_t len; uint32_t seq=0, idx=0, preds=0, resets=0;
    static analyzer_result_t r;
    analyzer_reset();
    while(fread(&ts,8,1,f)==1 && fread(&len,4,1,f)==1){
        if(len>sizeof buf){fseek(f,len,SEEK_CUR);continue;}
        if (fread(buf,1,len,f) != len) break;
        ++idx; ++seq;
        if(len>1518) continue;
        if(drop_every && (idx % drop_every)==0){ /* frame lost before analysis */
#ifdef NEW_API
            analyzer_note_capture_gap();
#else
            analyzer_reset();
#endif
            continue;
        }
        memset(&r,0,sizeof r);
        if(analyzer_process_ethernet_capture(buf,len,ts,seq,&r)){
#ifdef NEW_API
            if(r.stream_reset) ++resets;
#endif
            if(r.prediction_ready){ ++preds;
                if(!drop_every) printf("%u %d %08x %.7f %u\n",idx,(int)r.protocol,r.stream_key,r.primary_probability,r.primary_label);
            }
        }
    }
    analyzer_diagnostics_t dg; analyzer_get_diagnostics(&dg);
    fprintf(stderr,"frames=%u predictions=%u unsupported=%u malformed=%u stream_resets=%u\n",idx,preds,dg.unsupported_streams,dg.malformed_frames,resets);
    return 0;
}
