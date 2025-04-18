#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<math.h>
#include <string.h>

#undef DEBUG
#ifdef DEBUG
#define PRINT printf
#else
#define PRINT
#endif // DEBUG


// CAN hyper-period
int h = 5; // SampleTwo

// IDset of target ECU in ascending order of periodicity
int ECUIDs[] = {417, 451, 707, 977}; // SampleTwo.csv

// Periodicities of the IDs of target ECU in ascending order
float ECUIDPeriodicities[] = {0.025, 0.025, 0.05, 0.1}; // SampleTwo.csv

// number of consecuing skips allowed to ensure stability
int ctrlSkipLimit[] = {3,2,2,1};

// No of control tasks in target ECU
int ECUCount = 4; // SampleTwo.csv


// minimum attack window length for successful transmissions
int minAtkWinLen = 111;

// Maximum attack window: this is to reduce space for attack window per instance
int minDlc = 1;

// Bus speed
float busSpeed = 500; // in kbps

// CLF criteria


// This is for verification
// If we want to check the analysis for a specific control task
int testID = 461;

struct Instance{
    int index;
    int atkWinLen; // Length of attackwindow = total packet length of the high priority preceeding messages
    int atkWinCount; // count of high priority messages preceding the target one
    int attackable; //  if the attack window is sufficient for attacking
    int *atkWin; // List of high priority messages preceeding the target instance
    int *insWin;
};

struct Message
{
    int ID;
    float periodicity;
    int count; // no of instances per CAN hyper period
    int DLC; // Data field length in terms of byte
    float txTime; // Transmission time of a message
    int atkWinLen; // Total length of attack window in bits
    int tAtkWinLen; // temporary variable
    int tAtkWinCount; // temporary variable
    int readCount; // no. of times it is read from CAN traffic
    int *tAtkWin; // temporary variable
    int *tInsWin; // temporary variable
    struct Instance *instances; // pointer to an instance array
    int *sortedASP; // sorted list of the instance numbers wrt attack success probability (attack window length)
    int *pattern; // execution pattern of the control task
    int skipLimit; // instance number from when the first skip starts. 0 indicates first instance
};

/** *ID_set= list of structure of type ID,
n = no. of items in ID_set
IDs = list of IDs transmitted to CAN from victim
**/
void InitializeECU(struct Message **IDSet)
{
    PRINT("\n Init ecu started");
    int upper=64, lower=0, i=0,j=0;

    for(i=0;i<ECUCount;i++)
    {
        (*IDSet)[i].ID = ECUIDs[i];
        (*IDSet)[i].periodicity = ECUIDPeriodicities[i];
        (*IDSet)[i].count = ceil(h/(*IDSet)[i].periodicity);
        (*IDSet)[i].DLC = 0;
        (*IDSet)[i].atkWinLen = 0;
        (*IDSet)[i].tAtkWinLen = 0;
        (*IDSet)[i].tAtkWinCount = 0;
        (*IDSet)[i].readCount = 0;
        (*IDSet)[i].instances = (struct Instance*)calloc((*IDSet)[i].count,sizeof(struct Instance));
        (*IDSet)[i].sortedASP = (int*)calloc((*IDSet)[i].count,sizeof(int));
        (*IDSet)[i].pattern = (int*)calloc((*IDSet)[i].count,sizeof(int));
        (*IDSet)[i].skipLimit = ctrlSkipLimit[i];
        for(j=0;j<(*IDSet)[i].count;j++)
        {
            (*IDSet)[i].instances[j].index = j;
            (*IDSet)[i].instances[j].atkWinLen = 0;
            (*IDSet)[i].instances[j].attackable = 0;
            (*IDSet)[i].instances[j].atkWinCount = 0;
            (*IDSet)[i].pattern[j] = 1;
        }
    }
    PRINT("\n Init ecu ended");
}

/** *This function parse the CAN trraffic from sampleOne.csv
We retrieve ID, DLC, and transmission start time
**/
int InitializeCANTraffic(struct Message **can)
{
    int row = 0, column = 0, line = 0;
    FILE* fp = fopen("SampleTwo.csv", "r");

    if (!fp)
        printf("Can't open file\n");
    else
    {
        char buffer[1024];

        while (fgets(buffer,3000, fp))
        {
            column = 0;
            row++;
            // Splitting the data
            char* value = strtok(buffer, ",");
            if(value!="Chn" || value!="Logging" || row>1)
            {
                line++;
                *can = (struct Message *)realloc(*can,sizeof(struct Message)*line);
                while (value) {
                    // This is for our ECU-setup and CAN log
                    if (column == 1 && line>1) {
                        (*can)[line-2].ID = (int)strtol(value, NULL, 16);//atoi(value);
                    }
                    if (column == 2 && line>1) {
                        (*can)[line-2].DLC = atoi(value);
                    }
                    if (column == 11 && line>1) {
                        (*can)[line-2].txTime = atof(value);
                    }
                    value = strtok(NULL, ",");
                    column++;
                }
            }
        }
        fclose(fp);
        }
        line = line-2;
        *can = (struct Message *)realloc(*can,sizeof(struct Message)*line);
        return line;
}

// merge two sorted arrays
void IntMerge(int *arr, int *temp, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    int L[n1], R[n2], L1[n1], R1[n2];

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
    {
        L[i] = arr[l + i];
        L1[i] = temp[l+i];
    }for (j = 0; j < n2; j++){
        R[j] = arr[m + 1 + j];
        R1[j] = temp[m + 1 + j];
    }

    // Merge the temp arrays back into arr[l..r
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i] <= R[j]) {
            arr[k] = L[i];
            temp[k] = L1[i];
            i++;
        }
        else {
            arr[k] = R[j];
            temp[k] = R1[j];
            j++;
        }
        k++;
    }

    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        arr[k] = L[i];
        temp[k] = L1[i];
        i++;
        k++;
    }

    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        arr[k] = R[j];
        temp[k] = R1[j];
        j++;
        k++;
    }
}

// To sort an array of integers
// l and r are left and right most index of arr
void IntSort(int *arr1, int *arr2, int l, int r)
{
    if (l < r) {
        int m = l + (r - l) / 2;

        // Sort first and second halves
        IntSort(arr1, arr2, l, m);
        IntSort(arr1, arr2, m + 1, r);
        IntMerge(arr1, arr2, l, m, r);
    }

}

// Merge two lists of mesages sorted by attack length
void MsgMergeByAtkWinLen(struct Message **arr, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    struct Message *L = (struct Message *)calloc(n1,sizeof(struct Message));
    struct Message *R = (struct Message *)calloc(n2,sizeof(struct Message));

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
        L[i] = (*arr)[l + i];
    for (j = 0; j < n2; j++)
        R[j] = (*arr)[m + 1 + j];

    // Merge the temp arrays back into arr[l..r
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i].atkWinLen <= R[j].atkWinLen) {
            (*arr)[k] = L[i];
            i++;
        }
        else {
            (*arr)[k] = R[j];
            j++;
        }
        k++;
    }

    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        (*arr)[k] = L[i];
        i++;
        k++;
    }

    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        (*arr)[k] = R[j];
        j++;
        k++;
    }
    PRINT("\n In MsgMergeByAtkWinLen: Freeing L");
    free(L);
    PRINT("\n In MsgMergeByAtkWinLen: Freeing R");
    free(R);
}


// To sort a message list by their attack length in ascending order
void MsgSortByAtkWinLen(struct Message **candidates, int l, int r)
{
        if (l < r) {
            int m = l + (r - l) / 2;
            // Sort first and second halves
            MsgSortByAtkWinLen(candidates, l, m);
            MsgSortByAtkWinLen(candidates, m + 1, r);
            MsgMergeByAtkWinLen(candidates, l, m, r);
    }

}

// Merge two lists of instances sorted by attack length
void InsMergeByAtkWinLen(struct Instance **instances, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;

    // Create temp arrays
    struct Instance *L = (struct Instance *)calloc(n1,sizeof(struct Instance));
    struct Instance *R = (struct Instance *)calloc(n2,sizeof(struct Instance));

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < n1; i++)
        L[i] = (*instances)[l + i];
    for (j = 0; j < n2; j++)
        R[j] = (*instances)[m + 1 + j];

    // Merge the temp arrays back into arr[l..r]
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2) {
        if (L[i].atkWinLen >= R[j].atkWinLen) {
            (*instances)[k] = L[i];
            i++;
        }
        else {
            (*instances)[k] = R[j];
            j++;
        }
        k++;
    }
    // Copy the remaining elements of L[],
    // if there are any
    while (i < n1) {
        (*instances)[k] = L[i];
        i++;
        k++;
    }
    // Copy the remaining elements of R[],
    // if there are any
    while (j < n2) {
        (*instances)[k] = R[j];
        j++;
        k++;
    }
    PRINT("\n In InsMergeByAtkWinLen: Freeing L");
    free(L);
    PRINT("\n In InsMergeByAtkWinLen: Freeing R");
    free(R);
}

// To sort the instances in descending order of atk success prob. i.e. atk win len
void InsSortByAtkWinLen(struct Instance **instances, int l, int r)
{
    if (l < r) {
            int m = l + (r - l) / 2;
            // Sort first and second halves
            InsSortByAtkWinLen(instances, l, m);
            InsSortByAtkWinLen(instances, m + 1, r);
            InsMergeByAtkWinLen(instances, l, m, r);
    }
}

int BinarySearch(int *arr, int l, int r, int x)
{
    while (l <= r) {
        int m = l + (r - l) / 2;

        // Check if x is present at mid
        if (arr[m] == x)
        {
            //printf("\n array element=%d, item to be searched=%d", arr[m],x);
            return m;
        }
        // If x greater, ignore left half
        if (arr[m] < x)
            l = m + 1;

        // If x is smaller, ignore right half
        else
            r = m - 1;
    }

    // If we reach here, then element was not present
    return -1;
}

// Returns the intersection of two arrays and b
// Update attack window of instance ins with the common messages
void CommonMessages(int *a, int *x, int n_a, int *b, int *y, int n_b, struct Instance *ins)
{
    int j = 0, i=0, k=0;
    int atkWinCount = 0;
    int *intersection;
    int *intersection1;
    if(n_a<=n_b)
    {
        IntSort(a, x, 0, n_a-1);
        for(i=0;i<n_b;i++)
        {
            if(BinarySearch(a, 0, n_a-1, b[i])>=0)
            {
                j++;
                if(j==1)
                {
                    intersection = (int *)calloc(j, sizeof(int));
                    intersection1 = (int *)calloc(j, sizeof(int));
                }else
                {
                    intersection = (int *)realloc(intersection, sizeof(int)*j);
                    intersection1 = (int *)realloc(intersection1, sizeof(int)*j);
                }
                intersection[j-1] = b[i];
                intersection1[j-1] = y[i];
                atkWinCount++;
            }
        }
    }
    else
    {
        IntSort(b, y, 0, n_b-1);
        for(i=0;i<n_a;i++)
        {
            if(BinarySearch(b, 0, n_b-1, a[i])>=0)
            {
                j++;
                if(j==1)
                {
                    intersection = (int *)calloc(j, sizeof(int));
                    intersection1 = (int *)calloc(j, sizeof(int));
                }else
                {
                    intersection = (int *)realloc(intersection, sizeof(int)*j);
                    intersection1 = (int *)realloc(intersection1, sizeof(int)*j);
                }
                intersection[j-1] = a[i];
                intersection1[j-1] = x[i];
                atkWinCount++;
            }
        }
    }
    PRINT("\n In common: freeing atkWin");
    free((*ins).atkWin);
    PRINT("\n In common: freeing insWin");
    free((*ins).insWin);
    (*ins).atkWinCount = atkWinCount;
    PRINT("\n In Common: atkWinCount = %d",atkWinCount);
    if(atkWinCount>0)
    {
        (*ins).atkWin = (int *)calloc(atkWinCount, sizeof(int));
        (*ins).insWin = (int *)calloc(atkWinCount, sizeof(int));
        for(int i=0;i<atkWinCount;i++)
        {
            (*ins).atkWin[i] = intersection[i];
            (*ins).insWin[i] = intersection1[i];
        }
        PRINT("\n In common: freeing intersection1");
        free(intersection);
        PRINT("\n In common: freeing intersection2");
        free(intersection1);
    }
}

int GetCurrentInstance(struct Message **candidates, int canDataID)
{
    int i = 0;

    for(i=0;i<ECUCount;i++)
    {
        if((*candidates)[i].ID == canDataID)
        {
            return (*candidates)[i].readCount;
        }
    }

    return -1;
}

void AnalyzeCANTraffic(struct Message *CANTraffic, int CANCount, struct Message **candidates)
{
    int j=0,i=0,k=0,l=0,insNo = 0;
    float txStart = 0, txEnds = 0, nextTxStart = 0;
    float maxIdle = (minDlc*8+47)/(busSpeed*1000);
    struct Message CANPacket, candidate;
    while(j<CANCount-1)
    {
        CANPacket = CANTraffic[j];
        txStart = CANPacket.txTime;
        txEnds = ((CANPacket.DLC)*8 + 47)/(busSpeed*1000);
        nextTxStart = CANTraffic[j+1].txTime;
        PRINT("\n Checking for CAN ID (%d):%d ***********************",j,CANPacket.ID);
        for(i=0;i<ECUCount;i++)
        {
            PRINT("\n Checinkg for ECU ID:%d ***********************",(*candidates)[i].ID);
            k = 0;
            for (l = (*candidates)[i].readCount; l < (*candidates)[i].count; l++)
            {
                if((*candidates)[i].pattern[l]==0)
                    k++;
            }
            if((*candidates)[i].ID == testID)
            {
                printf("\n max idle time=%f",maxIdle);
                printf("\n gap = %f",(nextTxStart - (txStart + txEnds)));
            }
            if((CANPacket.ID > (*candidates)[i].ID) || ((nextTxStart - (txStart + txEnds))>maxIdle && (CANPacket.ID != (*candidates)[i].ID))) // If CAN packet is of lower priority or there is an idle period in between
            {
                if((*candidates)[i].tAtkWinLen>0)
                {
                    PRINT("\n freeing tAtkWin in low priority case");
                    free((*candidates)[i].tAtkWin);
                    PRINT("\n freeing tInsWin in low priority case");
                    free((*candidates)[i].tInsWin);
                    (*candidates)[i].tAtkWinLen = 0;
                    (*candidates)[i].tAtkWinCount = 0;
                }
            }
            else if((CANPacket.ID < (*candidates)[i].ID)) // If CAN packet belongs to attack window
            {
                insNo = GetCurrentInstance(candidates,CANPacket.ID);
                // what is instance no. of the CANPacket if it is coming from target ECU
                (*candidates)[i].tAtkWinCount = (*candidates)[i].tAtkWinCount + 1;
                (*candidates)[i].tAtkWinLen = (*candidates)[i].tAtkWinLen + (CANPacket.DLC)*8 + 47;
                if((*candidates)[i].tAtkWinCount == 1)
                {
                    (*candidates)[i].tAtkWin = (int *)calloc((*candidates)[i].tAtkWinCount,sizeof(int));
                    (*candidates)[i].tInsWin = (int *)calloc((*candidates)[i].tAtkWinCount,sizeof(int));
                }
                else
                {
                    (*candidates)[i].tAtkWin = (int *)realloc((*candidates)[i].tAtkWin,sizeof(int)*(*candidates)[i].tAtkWinCount);
                    (*candidates)[i].tInsWin = (int *)realloc((*candidates)[i].tInsWin,sizeof(int)*(*candidates)[i].tAtkWinCount);
                }
                (*candidates)[i].tAtkWin[(*candidates)[i].tAtkWinCount-1] = CANPacket.ID;
                (*candidates)[i].tInsWin[(*candidates)[i].tAtkWinCount-1] = insNo;
            }
            else
            {
                if((*candidates)[i].readCount>=(*candidates)[i].count) // 2nd hyper period onwards
                {

                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen
                                = (int)fmin((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen, (*candidates)[i].tAtkWinLen);
                    if((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen == 0)
                    {
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount = 0;
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    }
                    else{
                    CommonMessages((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin,
                                   (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin,
                                   (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,
                                   (*candidates)[i].tAtkWin,
                                   (*candidates)[i].tInsWin,
                                   (*candidates)[i].tAtkWinCount,
                                   &(*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count]);
                    }
                }
                else // 1st hyper period
                {

                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinLen = (*candidates)[i].tAtkWinLen;
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount = (*candidates)[i].tAtkWinCount;
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin =
                                                            (int *)calloc((*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount,sizeof(int));
                    for(l=0;l<(*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWinCount;l++)
                    {
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].atkWin[l] = (*candidates)[i].tAtkWin[l];
                        (*candidates)[i].instances[((*candidates)[i].readCount+k)%(*candidates)[i].count].insWin[l] = (*candidates)[i].tInsWin[l];
                    }
                }

                if((*candidates)[i].tAtkWinLen>0)
                {
                    PRINT("\n freeing tAtkWin at end");
                    free((*candidates)[i].tAtkWin);
                    PRINT("\n freeing tInsWin at end");
                    free((*candidates)[i].tInsWin);
                    (*candidates)[i].tAtkWinLen = 0;
                    (*candidates)[i].tAtkWinCount = 0;
                }
                (*candidates)[i].readCount=(*candidates)[i].readCount+k+1;
            }
        }
        j++;
    }
}

// This function checks if a new skip is introduced in the existing pattern
// the CLF criteria is violated or not.
int IfSkipPossible(int *patternList, int patternLen, int skipLimit, int newSkipPosition)
{
    int i=0, sum=0;
    patternList[newSkipPosition] = 0;

    for(i=0;i<patternLen;i++)
    {
        if(patternList[i%patternLen]==patternList[(i+1)%patternLen] && patternList[i%patternLen]==0)
            sum = sum + 1;
        else
            sum = 0;
        if(sum>=skipLimit)
        {
            patternList[newSkipPosition] = 1;
            return 0;
        }
    }

    return 1;
}

// This function checks if 'item' belongs to attack window 'atkWin'
// ** we have to see which instance of higher priority task belongs to atkWin
int CheckMembership(int *atkWin, int atkWinLen, int item)
{
    int i=0;

    for(i=0;i<atkWinLen;i++)
    {
        if(atkWin[i] == item)
            return i;
    }

    return -1;
}


// Writes the final candidate information to a CSV file.
void SaveFinalCandidatesCSV(struct Message *candidates, int ECUCount) {
    FILE *fp = fopen("final_candidates.csv", "w");
    if (!fp) {
        perror("Error opening final_candidates.csv");
        return;
    }
    
    // Write CSV header
    fprintf(fp, "CandidateID,Periodicity,InstanceIndex,Attackable,AtkWinLen,AtkWinCount,AtkWinMessages,InsWinMessages\n");

    for (int i = 0; i < ECUCount; i++) {
        // Loop over each instance for candidate i
        for (int j = 0; j < candidates[i].count; j++) {
            struct Instance *inst = &candidates[i].instances[j];
            // Write candidate and instance basic info.
            fprintf(fp, "%d,%.3f,%d,%d,%d,%d,", 
                    candidates[i].ID,
                    candidates[i].periodicity,
                    inst->index,
                    inst->attackable,
                    inst->atkWinLen,
                    inst->atkWinCount);
            
            // Write the attack window message IDs (if any)
            if (inst->atkWinCount > 0 && inst->atkWin != NULL) {
                // Open quotes to encapsulate list in case it contains commas
                fprintf(fp, "\"");
                for (int k = 0; k < inst->atkWinCount; k++) {
                    fprintf(fp, "%d", inst->atkWin[k]);
                    if (k < inst->atkWinCount - 1)
                        fprintf(fp, ";");
                }
                fprintf(fp, "\",");
            } else {
                fprintf(fp, "\"\",");
            }
            
            // Write the corresponding instance numbers (if any)
            if (inst->atkWinCount > 0 && inst->insWin != NULL) {
                fprintf(fp, "\"");
                for (int k = 0; k < inst->atkWinCount; k++) {
                    fprintf(fp, "%d", inst->insWin[k]);
                    if (k < inst->atkWinCount - 1)
                        fprintf(fp, ";");
                }
                fprintf(fp, "\"");
            } else {
                fprintf(fp, "\"\"");
            }
            
            // End line for this instance.
            fprintf(fp, "\n");
        }
    }
    
    fclose(fp);
    printf("\nFinal candidates saved to final_candidates.csv\n");
}

int main()
{
    int i = 0, sum = 0, j = 0, k = 0, l = 0, CANCount = 0, ifSkip = 0, insToSkipObf1 = 0, insToSkipObf2 = 0, initDectec = 0;
    float smallestPeriod = 0;

    srand(time(0));

    struct Message *CANTraffic = (struct Message *)calloc(CANCount+1, sizeof(struct Message));
    struct Message *candidates = (struct Message *)calloc(ECUCount, sizeof(struct Message));
    struct Message *sortecCandidates = (struct Message *)calloc(1, sizeof(struct Message));

    CANCount = InitializeCANTraffic(&CANTraffic);
    InitializeECU(&candidates);
    
    while(l <= 10)
    {
        printf("\nAnalyzing the CAN traffic.......................");
        AnalyzeCANTraffic(CANTraffic, CANCount, &candidates);
        for(i = 0; i < ECUCount; i++)
        {
            sum = 0;
            for(j = 0; j < candidates[i].count; j++)
            {
                if(candidates[i].instances[j].atkWinLen >= minAtkWinLen)
                    candidates[i].instances[j].attackable = 1;
                else
                    candidates[i].instances[j].attackable = 0;
                sum += candidates[i].instances[j].atkWinLen;
            }
            candidates[i].atkWinLen = sum / candidates[i].count;
        }

        // Sort the attack window of each instance of each candidate
        for(i = 0; i < ECUCount; i++)
        {
            InsSortByAtkWinLen(&candidates[i].instances, 0, candidates[i].count - 1);
            // Printing the status of each candidate before applying obfuscation policies
            printf("\n Candidate ID = %d", candidates[i].ID);
            printf("\n--------------------------------------------------");
            for(j = 0; j < candidates[i].count; j++)
            {
                printf("\n %d: Instance = %d: attack win len = %d, attack win count = %d", 
                       j, candidates[i].instances[j].index, 
                       candidates[i].instances[j].atkWinLen, 
                       candidates[i].instances[j].atkWinCount);
                printf("\n Attack window:");
                for(k = 0; k < candidates[i].instances[j].atkWinCount; k++)
                    printf("%d(instance=%d)  ", candidates[i].instances[j].atkWin[k],
                                             candidates[i].instances[j].insWin[k]);
            }
            printf("\n Pattern: ");
            for(j = 0; j < candidates[i].count; j++)
                printf("%d ", candidates[i].pattern[j]);
            printf("\n===========================================================================================");
        }

        // Apply obfuscation policies (your existing code here)
        printf("\n Obfuscation policy initiated....................");
        for(i = 0; i < ECUCount; i++)
        {
            ifSkip = 0;
            insToSkipObf1 = 0;
            insToSkipObf2 = 0;
            j = 0;
            printf("\nCandidate ID = %d", candidates[i].ID);
            printf("\n Checking obfuscation 1");
            while(j < candidates[i].count)
            {
                if(!candidates[i].instances[j].attackable || !candidates[i].pattern[candidates[i].instances[j].index])
                    j++;
                else break;
            }
            printf("\n sorted order = %d", j);

            if(j < candidates[i].count)
            {
                insToSkipObf1 = candidates[i].instances[j].index;
                ifSkip = IfSkipPossible(candidates[i].pattern, candidates[i].count, candidates[i].skipLimit, insToSkipObf1);
            }
            if(ifSkip) // Obfuscation 1 is possible
                continue;
            else // Checking obfuscation 2
            {
                printf("\n Checking obfuscation 2");
                for(j = 0; j < i; j++)
                {
                    printf("\n Checking if higher priority task %d belongs to atk window", candidates[j].ID);
                    insToSkipObf2 = CheckMembership(candidates[i].instances[insToSkipObf1].atkWin, candidates[i].instances[insToSkipObf1].atkWinCount, candidates[j].ID);
                    if(insToSkipObf2 >= 0)
                    {
                        printf("\n Instance %d of %d belongs to atk win", insToSkipObf2, candidates[j].ID);
                        ifSkip = IfSkipPossible(candidates[j].pattern, candidates[j].count, ctrlSkipLimit[j], insToSkipObf2);
                        if(ifSkip)
                            break;
                    }
                }
                if(!ifSkip)
                { // Checking obfuscation 3
                    printf("\n Checking obfuscation 3");
                    for(k = i - 1; k >= 0; k--)
                    {
                        if(candidates[i].periodicity != candidates[k].periodicity)
                            break;
                    }
                    if(k != i - 1)
                    {
                        k++;
                        if(candidates[i].periodicity == candidates[k].periodicity && 
                           CheckMembership(candidates[i].instances[insToSkipObf1].atkWin, candidates[i].instances[insToSkipObf1].atkWinCount, candidates[k].ID) >= 0)
                        {
                            struct Message temp = candidates[k];
                            candidates[k] = candidates[i];
                            candidates[i] = temp;
                        }
                    }
                }
            }
        }
        l++;
    }

    // Save the final candidates to a CSV file.
    SaveFinalCandidatesCSV(candidates, ECUCount);

    free(candidates);
    free(CANTraffic);
    return 0;
}
